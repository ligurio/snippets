//  Copyright 2018 ООО "ОЛИМП". Released under GPLv3 in Russia.
//---------------------------------------------------------------------------------------------------
//  Пример программы работы с устройством RODOS-3. Версия 1.01
//---------------------------------------------------------------------------------------------------
//  www.silines.ru
//  www.olimp-z.ru
//---------------------------------------------------------------------------------------------------
#define R3_VID 0x20A0
#define R3_PID 0x4173
//---------------------------------------------------------------------------------------------------
#include <iostream>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <getopt.h>
#include <string>
#include <memory>
#include "RODOS3.h"
using namespace std;
//---------------------------------------------------------------------------------------------------
struct flags_t
{
    bool no_flags;
    bool on;
    bool off;
    bool reset;
    bool all;
    bool read;
    unsigned int device_id;

    void init (void);
};
//---------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    std::ios::sync_with_stdio(false);

    int MAIN_RESULT = 1;
    flags_t flags;
    flags.init();

    //  Разбор переданных параметров
    const char* short_options = "hnftra";

        const struct option long_options[] = {
            {"help",no_argument,NULL,'h'},
            {"id",required_argument,NULL,'i'},
            {"on",no_argument,NULL,'n'},
            {"off",no_argument,NULL,'f'},
            {"reset",no_argument,NULL,'t'},
            {"read",no_argument,NULL,'r'},
            {"all",no_argument,NULL,'a'},
            {NULL,0,NULL,0}
        };

        int rez;
        int option_index;

        while ((rez=getopt_long(argc,argv,short_options,long_options,&option_index))!=-1)
        {
            switch(rez){
                case 'h': {
                    cout << " Используйте параметры\n"
                            "   --help, -h - вызов справки\n"
                            "   --id ID    - обращение к RODOS-3 с соответствующим ID\n"
                            "   --all, -a  - для выполнения на всех RODOS-3\n"
                            "   --on, -n   - включить нагрузку\n"
                            "   --off, -f  - отключить нагрузку\n"
                            "   --reset, -t  - перезагрузить нагрузку\n"
                            "   --read, -r - считать текущее состояние реле\n"
                            "   или запустите без параметров для получения списка всех устройств и их ID\n"
                         << flush;
                    flags.no_flags = false;
                    break;
                }
                case 'i': {
                    flags.device_id = stoi(optarg);
                    flags.no_flags = false;
                    break;
                }
                case 'n': {
                    flags.on = true;
                    flags.no_flags = false;
                    break;
                }
                case 'f': {
                    flags.off = true;
                    flags.no_flags = false;
                    break;
                }
                case 't': {
                    flags.reset = true;
                    flags.no_flags = false;
                    break;
                }
                case 'r': {
                    flags.read = true;
                    flags.no_flags = false;
                    break;
                }
                case 'a': {
                    flags.all = true;
                    flags.no_flags = false;
                    break;
                }
                case '?': default: {
                    cout << "Неизвестный параметр" << endl;
                    break;
                }
            }
        }

    if (((flags.on)&&(flags.off)) || ((flags.all)&&(flags.device_id))) { cout << "Неверно заданы параметры\n"; MAIN_RESULT = -1; }
    else
    {
        //  Подключение к RODOS-3 и исполнение команд
        struct hid_device_info *devs;
        int device_counter = 0;

        devs = hid_enumerate(R3_VID, R3_PID);

        if (flags.no_flags) cout << "Поиск устройств..." << endl;

        while (devs)
        {
            std::unique_ptr<RODOS3_t> R3 (new RODOS3_t(devs->path));

            if (R3->CHECK_HANDLE() == false) cout << "Ошибка подключения" << endl;
            else
            {
                wstring PrString;
                R3->Read_Device_Production_String(PrString);

                if (flags.no_flags) {
                    wcout << PrString << flush;
                    cout << " ID: " << R3->Get_Device_ID();
                }

                if (!wcscmp(PrString.c_str(), L"RODOS-3"))
                {
                    device_counter++;
                    if (((flags.device_id == 0)&&(flags.all)) || (flags.device_id == R3->Get_Device_ID()))
                    {
                        if (flags.on)
                        {
                            R3->STATE__ON();
                            cout <<  "ID: " << R3->Get_Device_ID() << " нагрузка включена" << endl;
                        }
                        if (flags.off)
                        {
                            R3->STATE__OFF();
                            cout <<  "ID: " << R3->Get_Device_ID() << " нагрузка отключена" << endl;
                        }
                        if (flags.reset)
                        {
                            unsigned char PS;
                            if (R3->STATE__READ(PS))
                            {
                                if (PS==0x19) {
                            		R3->STATE__ON();
                            		cout <<  "ID: " << R3->Get_Device_ID() << " нагрузка включена" << endl;
                                }
                                else {
                            		R3->STATE__OFF();
                            		cout <<  "ID: " << R3->Get_Device_ID() << " нагрузка выключена" << endl;
                            		R3->STATE__ON();
                            		cout <<  "ID: " << R3->Get_Device_ID() << " нагрузка включена" << endl;
                                }
                            }
                            else { cout << "Ошибка чтения" << endl; MAIN_RESULT = -1; }
                        }
                        if (flags.read)
                        {
                            unsigned char PS;
                            if (R3->STATE__READ(PS))
                            {
                                if (PS==0x19) cout <<  "ID: " << R3->Get_Device_ID() << " нагрузка отключена" << endl;
                                else cout <<  "ID: " << R3->Get_Device_ID() << " нагрузка включена" << endl;
                            }
                            else { cout << "Ошибка чтения" << endl; MAIN_RESULT = -1; }
                        }
                    } else cout << endl;
                } else cout << endl;
            }

            R3.reset();
            devs = devs->next;
        }
        if (flags.no_flags) cout << "Найдено RODOS-3: " << device_counter << endl;
    }

    return MAIN_RESULT;
}
//---------------------------------------------------------------------------------------------------
void flags_t::init(void)
{
    no_flags = true;
    on = false;
    off = false;
    all = false;
    read = false;
    device_id = 0;
}
//---------------------------------------------------------------------------------------------------
