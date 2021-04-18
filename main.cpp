#include <QCoreApplication>

// CpuId
#include <arpa/inet.h>
#include <fstream>
#include <unistd.h>
#include <cstring>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <QDebug>
#include <QDateTime>



#include <base64.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1

#include "aes.hpp"


#include "softlicense.h"

static bool get_cpu_id_by_asm(std::string & cpu_id)
{
    cpu_id.clear();

    unsigned int s1 = 0;
    unsigned int s2 = 0;
    asm volatile
    (
        "movl $0x01, %%eax; \n\t"
        "xorl %%edx, %%edx; \n\t"
        "cpuid; \n\t"
        "movl %%edx, %0; \n\t"
        "movl %%eax, %1; \n\t"
        : "=m"(s1), "=m"(s2)
    );

    if (0 == s1 && 0 == s2)
    {
        return(false);
    }

    char cpu[32] = { 0 };
    snprintf(cpu, sizeof(cpu), "%08X%08X", htonl(s2), htonl(s1));
    std::string(cpu).swap(cpu_id);

    return(true);
}

static void parse_cpu_id(const char * file_name, const char * match_words, std::string & cpu_id)
{
    cpu_id.c_str();

    std::ifstream ifs(file_name, std::ios::binary);
    if (!ifs.is_open())
    {
        return;
    }

    char line[4096] = { 0 };
    while (!ifs.eof())
    {
        ifs.getline(line, sizeof(line));
        if (!ifs.good())
        {
            break;
        }

        const char * cpu = strstr(line, match_words);
        if (NULL == cpu)
        {
            continue;
        }
        cpu += strlen(match_words);

        while ('\0' != cpu[0])
        {
            if (' ' != cpu[0])
            {
                cpu_id.push_back(cpu[0]);
            }
            ++cpu;
        }

        if (!cpu_id.empty())
        {
            break;
        }
    }

    ifs.close();
}

static bool get_cpu_id_by_system(std::string & cpu_id)
{
    cpu_id.c_str();

    const char * dmidecode_result = ".dmidecode_result.txt";
    char command[512] = { 0 };
    snprintf(command, sizeof(command), "dmidecode -t 4 | grep ID > %s", dmidecode_result);

    if (0 == system(command))
    {
        parse_cpu_id(dmidecode_result, "ID:", cpu_id);
    }

    unlink(dmidecode_result);

    return(!cpu_id.empty());
}

static bool get_cpu_id(std::string & cpu_id)
{
    if (get_cpu_id_by_asm(cpu_id))
    {
        return(true);
    }
    if (0 == getuid())
    {
        if (get_cpu_id_by_system(cpu_id))
        {
            return(true);
        }
    }
    return(false);
}



int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

#if 0
    std::string cpu_id;

    get_cpu_id(cpu_id);
    qDebug() << cpu_id.c_str();
#elif 0

    std::string cpu_id;

    get_cpu_id(cpu_id);
    QString strTime = QDateTime::currentDateTime().toString("&yyyy-MM-dd");
    // 128bit key
    uint8_t key[16] =  {0};
    key[0] = '1';
    key[1] = '2';
    key[2] = '3';
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    cpu_id += strTime.toStdString();
    uint8_t *utext = new uint8_t[cpu_id.length()];
    for(int i = 0; i <  cpu_id.length();i++)
    {
        utext[i] = cpu_id.at(i);
    }

    qDebug() << "CPU_ID:" ;
    for (int i = 0; i < cpu_id.length(); ++i)
        printf("%c", utext[i]);
    printf("\n");

    qDebug() << "CPU_ID(uint8_t):" ;
    for (int i = 0; i < cpu_id.length(); ++i)
        printf("%x", utext[i]);
    printf("\n");

    AES_ECB_encrypt(&ctx, utext);

    qDebug() << "CPU_ID(aes):" ;

    for (int i = 0; i < cpu_id.length(); ++i)
        printf("%x", utext[i]);
    printf("\n");
    std::string stren_str =  base64_encode(utext,cpu_id.length());


    qDebug() << "CPU_ID(aes)(base64_encode):";
    qDebug() << stren_str.c_str();




    std::string  strde_str =  base64_decode(stren_str);

    qDebug() << "CPUID_AES,base64_decode str:";
    for (int i = 0; i < strde_str.length(); ++i)
        printf("%x", strde_str.at(i));
    printf("\n");

    qDebug() << "strde_str length:" << strde_str.length();
    qDebug() << "cpu_id length:" << cpu_id.length();
    for(int i = 0; i <  strde_str.length();i++)
    {
        utext[i] = strde_str.at(i);
    }
    AES_ECB_decrypt(&ctx,utext);

    qDebug() << "CPU_ID(uint8_t):" ;
    for (int i = 0; i < cpu_id.length(); ++i)
        printf("%x", utext[i]);
    printf("\n");

    qDebug() << "CPU_ID:" ;
    for (int i = 0; i < cpu_id.length(); ++i)
        printf("%c", utext[i]);
    printf("\n");

#elif 0

    SoftLicense _softlicense;
    std::string cpuid;
    if(!SoftLicense::get_cpu_id(cpuid))
    {
        qDebug() << "cannot ge cpuid ";
        return -1;
    }
    qDebug() << "cpuid:" << cpuid.c_str();
    qDebug() << "base64key:" <<_softlicense.getAesBase64Str(cpuid).c_str();


    std::string s_cpuid;
    std::string s_time;
    _softlicense.getCpuidAndTimeFromFile(s_cpuid,s_time);

    qDebug() << "从文件中获取cpuid和时间:" << s_cpuid.c_str() << "---" << s_time.c_str();


    if(_softlicense.isCpuidCurrectOrTimeisOver(s_cpuid,s_time))
    {
        qDebug() << "合法使用该软件的电脑";
    }
    else
    {
        qDebug() << "未经授权，或授权过期，不得继续使用";
    }

#else
    SoftLicense _softlicense;
    std::string cpuid;
    if(!SoftLicense::get_cpu_id(cpuid))
    {
        qDebug() << "cannot ge cpuid ";
        return -1;
    }
    qDebug() << "cpuid:" << cpuid.c_str();
    qDebug() << "base64key:" <<_softlicense.getAesBase64Str(cpuid).c_str();


    if(_softlicense.isCanUse())
    {
        qDebug() << "合法使用该软件的电脑";
    }
    else
    {
        qDebug() << "未经授权，或授权过期，不得继续使用";
    }
#endif //0


    return a.exec();
}
