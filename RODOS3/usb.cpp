#include "usb.h"
#include <iostream>
#include <unistd.h>
//------------------------------------------------------------
#define DEBUG
//------------------------------------------------------------
usb_t::usb_t(int VID, int PID)
{
    handle = hid_open(VID, PID, NULL);
    if (handle)
    {
        hid_get_product_string (handle, Product_String, 10);
        USB_GET_ID(Device_ID);
    }
}
//------------------------------------------------------------
usb_t::usb_t(char *hid_device_path)
{
    handle = hid_open_path(hid_device_path);
    if (handle)
    {
        hid_get_product_string (handle, Product_String, 10);
        USB_GET_ID(Device_ID);
    }
}
//------------------------------------------------------------
usb_t::~usb_t() {
    if (handle != NULL) hid_close(handle);
}
//------------------------------------------------------------
void usb_t::Sleep(int ms)
{
    usleep (ms*1000);
}
//------------------------------------------------------------
bool usb_t::CHECK_HANDLE() {
    if (handle == NULL) return false;
    else return true;
}
//------------------------------------------------------------
void usb_t::USB_BUF_CLEAR()
{   //  очистка буферов приёма и передачи
    for (int i=0; i<9; i++) { USB_BUFI[i]=0; USB_BUFO[i]=0; }
}
//------------------------------------------------------------
bool usb_t::USB_GET_FEATURE()
{   //  чтение в буфер из устройства
    bool RESULT=false;
    int i=3;   //  число попыток
    while (!RESULT & ((i--)>0))
    {
        try {
            if (hid_get_feature_report(handle, USB_BUFI, 9) == -1) RESULT = false;
            else RESULT = true;
        }
        catch (...) { RESULT=false; }
    }
#ifdef DEBUG
    if (!RESULT) std::cout << "Ошибка чтения из USB-устройства" << std::endl;
#endif
    return RESULT;
}
//------------------------------------------------------------
bool usb_t::USB_SET_FEATURE()
{   //  запись из буфера в устройство
    bool RESULT=true;
    try { hid_send_feature_report(handle, USB_BUFO, 9); }
    catch (...) { RESULT=false; }
#ifdef DEBUG
    if (!RESULT) std::cout << "Ошибка записи в USB-устройство" << std::endl;
#endif
    return RESULT;
}
//------------------------------------------------------------
bool usb_t::USB_GET_PORT(unsigned char &PS)
{   //  чтение состояния порта, 2ms
    USB_BUF_CLEAR();
    bool RESULT=false;
    USB_BUFO[1]=0x7E;
    int i=3;   //  число попыток
    while (!RESULT & ((i--)>0))
        if (USB_SET_FEATURE())
            if (USB_GET_FEATURE())
                if (USB_BUFI[1]==0x7E) { PS=USB_BUFI[2]; RESULT=USB_BUFI[3]==PS; }
                    else RESULT=false;
#ifdef DEBUG
    if (!RESULT) std::cout << "Ошибка чтения PORT" << std::endl;
#endif
    return RESULT;
}
//------------------------------------------------------------
bool usb_t::USB_SET_PORT(unsigned char PS)
{   //  запись состояния порта, 2ms
    USB_BUF_CLEAR();
    bool RESULT=false;
    USB_BUFO[1]=0xE7;
    USB_BUFO[2]=PS;
    int i=3;   //  число попыток
    while (!RESULT & ((i--)>0))
        if (USB_SET_FEATURE())
            if (USB_GET_FEATURE())
                 { RESULT=(USB_BUFI[1]==0xE7)&(USB_BUFI[2]==PS)&(USB_BUFI[3]==PS); }
#ifdef DEBUG
    if (!RESULT) std::cout << "Ошибка записи PORT" << std::endl;
#endif
    return RESULT;
}
//------------------------------------------------------------
bool usb_t::USB_GET_FAMILY(unsigned char &FAMILY)
{   //  чтение группового кода устройства, 2ms
    USB_BUF_CLEAR();
    bool RESULT=false;
    USB_BUFO[1]=0x1D;
    int i=3;   //  число попыток
    while (!RESULT & ((i--)>0))
        if (USB_SET_FEATURE())
            if (USB_GET_FEATURE())
                if (USB_BUFI[1]==0x1D) { RESULT=true; FAMILY=USB_BUFI[2]; }
                    else RESULT=false;
#ifdef DEBUG
    if (!RESULT) std::cout << "Ошибка чтения FAMILY" << std::endl;
#endif
    return RESULT;
}
//------------------------------------------------------------
bool usb_t::USB_GET_SOFTV(unsigned int &SV)
{   //  чтение номера версии прошивки, 2ms
    USB_BUF_CLEAR();
    bool RESULT=false;
    USB_BUFO[1]=0x1D;
    int i=3;   //  число попыток
    while (!RESULT & ((i--)>0))
        if (USB_SET_FEATURE())
            if (USB_GET_FEATURE())
                if (USB_BUFI[1]==0x1D) { RESULT=true; SV=USB_BUFI[3]+(USB_BUFI[4]<<8); }
                    else RESULT=false;
#ifdef DEBUG
    if (!RESULT) std::cout << "Ошибка чтения номера версии прошивки" << std::endl;
#endif
    return RESULT;
}
//------------------------------------------------------------
bool usb_t::USB_GET_ID(unsigned int &ID)
{   //  чтение ID устройства, 2ms
    USB_BUF_CLEAR();
    bool RESULT=false;
    USB_BUFO[1]=0x1D;
    int i=3;   //  число попыток
    while (!RESULT & ((i--)>0))
        if (USB_SET_FEATURE())
            if (USB_GET_FEATURE())
                if (USB_BUFI[1]==0x1D) { RESULT=true; ID=(USB_BUFI[5]<<24)+(USB_BUFI[6]<<16)+(USB_BUFI[7]<<8)+USB_BUFI[8]; }
                    else RESULT=false;
#ifdef DEBUG
    if (!RESULT) std::cout << "Ошибка чтения ID устройства" << std::endl;
#endif
    return RESULT;
}
//------------------------------------------------------------
bool usb_t::USB_EE_RD(unsigned char ADR, unsigned char &DATA)
{   //  чтение EEPROM
    USB_BUF_CLEAR();
    bool RESULT=false;
    USB_BUFO[1]=0xE0;
    USB_BUFO[2]=ADR;
    int i=3;   //  число попыток
    while (!RESULT & ((i--)>0))
        if (USB_SET_FEATURE())
            if (USB_GET_FEATURE()) { RESULT=(USB_BUFI[1]==0xE0)&(USB_BUFI[2]==ADR); DATA=USB_BUFI[3]; }
#ifdef DEBUG
    if (!RESULT) std::cout << "Ошибка чтения EEPROM" << std::endl;
#endif
    return RESULT;
}
//------------------------------------------------------------
bool usb_t::USB_EE_WR(unsigned char ADR, unsigned char DATA)
{   //  запись EEPROM, 17ms, здесь аккуратно, не писать туда, куда не знаешь!!!
    USB_BUF_CLEAR();
    bool RESULT=false;
    USB_BUFO[1]=0x0E;
    USB_BUFO[2]=ADR;    USB_BUFO[3]=DATA;
    int i=3;   //  число попыток
    while (!RESULT & ((i--)>0))
        if (USB_SET_FEATURE())
            {
            usb_t::Sleep(15);   //  на запись в EEPROM
            if (USB_GET_FEATURE()) RESULT=(USB_BUFI[1]==0x0E)&(USB_BUFI[2]==ADR)&(USB_BUFI[3]==DATA);
            } else RESULT=false;
#ifdef DEBUG
    if (!RESULT) std::cout << "Ошибка записи EEPROM" << std::endl;
#endif
    return RESULT;
}
//------------------------------------------------------------
unsigned int usb_t::Get_Device_ID (void)
{
    return Device_ID;
}
//------------------------------------------------------------
void usb_t::Read_Device_Production_String (std::wstring &wString)
{
    for (int i=0; i<wcslen(Product_String); i++) wString += Product_String[i];
}
