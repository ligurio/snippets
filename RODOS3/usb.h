//------------------------------------------------------------
#ifndef USB_H
#define USB_H
//------------------------------------------------------------
#include "hidapi.h"
#include <string>
//------------------------------------------------------------
class usb_t
{
protected:
    usb_t(int VID, int PID);        //  Напрямую через VID, PID
    usb_t(char *hid_device_path);   //  Через hid_enumerate
    ~usb_t();
//---
private:
    hid_device      *handle;
    unsigned int    Device_ID;          //  уникальный номер устройства
    wchar_t         Product_String[10]; //  имя устройства
//---
protected:
    unsigned char   USB_BUFI [9];  //  буфер приёма
    unsigned char   USB_BUFO [9];  //  буфер передачи
//---
protected:
    void USB_BUF_CLEAR();
    bool USB_GET_FEATURE();
    bool USB_SET_FEATURE();
    bool USB_GET_PORT(unsigned char &PS);
    bool USB_SET_PORT(unsigned char PS);
    bool USB_GET_FAMILY(unsigned char &FAMILY);
    bool USB_GET_SOFTV(unsigned int &SV);
    bool USB_GET_ID(unsigned int &ID);
    bool USB_EE_RD(unsigned char ADR, unsigned char &DATA);
    bool USB_EE_WR(unsigned char ADR, unsigned char DATA);
//---
public:
    bool CHECK_HANDLE();
    static void Sleep(int ms);
    unsigned int Get_Device_ID (void);
    void Read_Device_Production_String (std::wstring &wString);
};
//------------------------------------------------------------
#endif // USB_H
//------------------------------------------------------------
