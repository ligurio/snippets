//------------------------------------------------------------
#ifndef _RODOS3_H_
#define _RODOS3_H_
//------------------------------------------------------------
#include "usb.h"
//------------------------------------------------------------
class RODOS3_t : public usb_t
{
public:
    RODOS3_t (int VID, int PID) : usb_t(VID, PID) {}
    RODOS3_t (char *path) : usb_t(path) {}
    ~RODOS3_t (){}
//-----------
public:
    bool    STATE__ON();
    bool    STATE__OFF();
    bool    STATE__READ(unsigned char &PS);
};
//------------------------------------------------------------
#endif  // _RODOS3_H_
//------------------------------------------------------------
