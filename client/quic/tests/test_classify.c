/* Unit-тест классификатора (client/quic/quic_classify.h).
 * Ручные случаи по MS-RDPBCGR + реальный заголовок PDU от xrdp 0.9.24 с TLS,
 * затем 1 млн случайных буферов под ASan/UBSan (не должно быть выходов за границы). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "quic_classify.h"

static int fails = 0;
static void expect(const char* name, QuicChannel got, QuicChannel want) {
    printf("%s %-52s -> %s\n", got == want ? "ok  " : "FAIL", name, QUIC_CHANNEL_NAMES[got]);
    if (got != want) { printf("      ожидалось %s\n", QUIC_CHANNEL_NAMES[want]); fails++; }
}
static void put16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

/* Собрать slow-path PDU: TPKT+X.224+MCS(SDIN/SDRQ, канал, длина PER 1/2 байта)
 * [+ security header] + Share Control (+ Share Data с pduType2), всего len байт. */
static size_t mk(uint8_t* b, size_t len, int sdin, uint16_t chan, int long_len,
                 int sec, uint16_t sec_flags, uint16_t pdutype, uint8_t type2) {
    memset(b, 0xAA, len);
    b[0]=0x03; b[1]=0; b[2]=(uint8_t)(len>>8); b[3]=(uint8_t)len; b[4]=0x02; b[5]=0xF0; b[6]=0x80;
    b[7]=(uint8_t)((sdin?26:25)<<2); b[8]=0; b[9]=0x07; b[10]=(uint8_t)(chan>>8); b[11]=(uint8_t)chan; b[12]=0x70;
    size_t off;
    if (long_len) { uint16_t l=(uint16_t)(len-15); b[13]=(uint8_t)(0x80|(l>>8)); b[14]=(uint8_t)l; off=15; }
    else { b[13]=(uint8_t)(len-14); off=14; }
    if (sec) { put16(b+off, sec_flags); put16(b+off+2, 0); off+=4; }
    put16(b+off, (uint16_t)(len-off)); put16(b+off+2, pdutype); put16(b+off+4, 0x03ea);
    b[off+6+8] = type2;
    return len;
}

int main(void) {
    static uint8_t b[4096];

    /* 1. Настоящий заголовок PDU от xrdp (TLS, без security header), снят трассировщиком */
    const uint8_t real[] = {0x03,0x00,0x07,0xad,0x02,0xf0,0x80,0x68,0x00,0x07,0x03,0xeb,0x70,0x87,0x9e,
        0x9e,0x07,0x17,0x00,0xf0,0x03,0xea,0x03,0x01,0x00,0x00,0x01,0x28,0x3e,0x02,0x21,0x9e,0x07};
    memset(b, 0x55, 1965); memcpy(b, real, sizeof real);
    expect("реальный xrdp/TLS: UPDATE, len 1965", quic_classify_server_pdu(b, 1965), QUIC_CHANNEL_GRAPHICS);

    /* 2. Тот же тип без/с security header, длины PER 1 и 2 байта */
    mk(b, 1965, 1, 1003, 1, 0, 0, 0x17, 0x02);
    expect("UPDATE, без sec header, PER 2 байта", quic_classify_server_pdu(b, 1965), QUIC_CHANNEL_GRAPHICS);
    mk(b, 80, 1, 1003, 0, 0, 0, 0x17, 0x02);
    expect("UPDATE, без sec header, PER 1 байт", quic_classify_server_pdu(b, 80), QUIC_CHANNEL_GRAPHICS);
    mk(b, 1965, 1, 1003, 1, 1, 0x0000, 0x17, 0x02);
    expect("UPDATE, с sec header (RDP security, NONE)", quic_classify_server_pdu(b, 1965), QUIC_CHANNEL_GRAPHICS);
    mk(b, 300, 1, 1003, 1, 0, 0, 0x17, 0x1B);
    expect("POINTER", quic_classify_server_pdu(b, 300), QUIC_CHANNEL_GRAPHICS);

    /* 3. Служебное на основном канале */
    mk(b, 200, 1, 1003, 1, 1, 0x0080, 0x17, 0x02);
    expect("sec header с флагом лицензии", quic_classify_server_pdu(b, 200), QUIC_CHANNEL_CONTROL);
    mk(b, 400, 1, 1003, 1, 0, 0, 0x11, 0);
    expect("Demand Active (pduType 1)", quic_classify_server_pdu(b, 400), QUIC_CHANNEL_CONTROL);
    mk(b, 40, 0, 1003, 0, 0, 0, 0x17, 0x1F);
    expect("Synchronize (pduType2 0x1F) от клиента", quic_classify_client_pdu(b, 40), QUIC_CHANNEL_CONTROL);
    mk(b, 60, 0, 1003, 0, 0, 0, 0x17, 0x1C);
    expect("slow-path INPUT от клиента", quic_classify_client_pdu(b, 60), QUIC_CHANNEL_INPUT);
    mk(b, 300, 1, 1003, 1, 1, 0x0008, 0x17, 0x02);
    b[19]=0x12; b[20]=0x34; /* «зашифрованное» содержимое: share ctrl не узнаётся */
    expect("зашифровано (SEC_ENCRYPT), не разобрать", quic_classify_server_pdu(b, 300), QUIC_CHANNEL_CONTROL);

    /* 4. Виртуальные каналы, fast-path, X.224 */
    mk(b, 1200, 1, 1005, 1, 0, 0, 0x17, 0x02);
    expect("SDIN канал 1005 (rdpsnd) — vchannel целиком", quic_classify_server_pdu(b, 1200), QUIC_CHANNEL_VCHANNEL);
    mk(b, 30, 0, 1007, 0, 0, 0, 0, 0);
    expect("SDRQ канал 1007 (drdynvc) от клиента", quic_classify_client_pdu(b, 30), QUIC_CHANNEL_VCHANNEL);
    b[0]=0x00; b[1]=0x20;
    expect("fast-path от сервера = графика", quic_classify_server_pdu(b, 30), QUIC_CHANNEL_GRAPHICS);
    expect("fast-path от клиента = ввод", quic_classify_client_pdu(b, 30), QUIC_CHANNEL_INPUT);
    const uint8_t x224_cr[] = {0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x0b,0x00,0x00,0x00};
    expect("X.224 Connection Request", quic_classify_client_pdu(x224_cr, sizeof x224_cr), QUIC_CHANNEL_CONTROL);
    expect("1 байт", quic_classify_client_pdu(b, 1), QUIC_CHANNEL_CONTROL);

    /* 5. Номер MCS-канала */
    mk(b, 100, 1, 1005, 0, 0, 0, 0x17, 2);
    printf("%s mcs канала 1005 = %d\n", quic_pdu_mcs_channel(b,100)==1005?"ok  ":"FAIL", quic_pdu_mcs_channel(b,100));
    if (quic_pdu_mcs_channel(b,100)!=1005) fails++;
    b[0]=0; if (quic_pdu_mcs_channel(b,100)!=-1) { puts("FAIL mcs fast-path"); fails++; } else puts("ok   mcs для fast-path = -1");

    /* 6. Случайные буферы: проверка границ под ASan (буфер ровно нужной длины на куче) */
    srand(7);
    for (long i = 0; i < 1000000; i++) {
        size_t len = (size_t)(rand() % 64) + (rand()%10==0 ? (size_t)(rand()%2000) : 0);
        uint8_t* p = malloc(len ? len : 1);
        for (size_t k = 0; k < len; k++) p[k] = (uint8_t)rand();
        if (len >= 14 && rand()%2) { p[0]=0x03; p[7]=(uint8_t)((rand()%2?25:26)<<2); p[10]=0x03; p[11]=0xEB; }
        volatile QuicChannel a = quic_classify_client_pdu(p, len), c = quic_classify_server_pdu(p, len);
        (void)a; (void)c;
        free(p);
    }
    puts("ok   1 млн случайных буферов без выхода за границы");

    printf(fails ? "ИТОГ: ОШИБОК %d\n" : "ИТОГ: всё верно\n", fails);
    return fails != 0;
}
