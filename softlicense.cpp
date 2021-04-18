#include "softlicense.h"
#include <fstream>
#include <QCoreApplication>
#include <QFile>
#include <QDebug>

SoftLicense::SoftLicense()
{
    memset(m_key,0,sizeof(m_key));

    for(int i = 0; i < M_KEY_LEN;i++)
    {
        m_key[i] = 0xA0 + i;
    }

    m_key[0] = 0xFE;
    m_key[M_KEY_LEN / 4] = 0x3F;
    m_key[M_KEY_LEN / 2] = 0x53;
    m_key[M_KEY_LEN - 1] = 0x7A;


    QString appPath = QCoreApplication::applicationDirPath();
    QString filePath = appPath + "/";
    filePath += LICENSE_PATH;

    m_license_path = filePath.toStdString();
}

int SoftLicense::setAesKey(uint8_t *key, int nlen)
{
    int mlen = nlen;
    if(mlen <= 0)
    {
        return -1;
    }

    if(mlen >= M_KEY_LEN)
    {
        mlen = M_KEY_LEN;
    }

    memcpy(m_key,key,mlen);

    //aes初始化
    initaes();
}

std::string SoftLicense::getAesBase64Str(const std::string &strbuff)
{
    std::string strdatebuff = strbuff;
    strdatebuff+= QDateTime::currentDateTime().toString("&yyyy-MM-dd").toStdString();
    uint8_t *utext = new uint8_t[strdatebuff.length()];
    for(int i = 0; i <  (int)strdatebuff.length();i++)
    {
        utext[i] = strdatebuff.at(i);
    }

    AES_ECB_encrypt(&m_ctx, utext);

    std::string stren_str =  base64_encode(utext,strdatebuff.length());
    delete [] utext;

    writeAesBase64StrToFile(stren_str,m_license_path);
    return stren_str;
}

int SoftLicense::writeAesBase64StrToFile(const std::string &strbuff, const std::string &fullpath)
{
    std::ofstream f;

    f.open(fullpath,std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
    f.write(strbuff.c_str(),strbuff.length());
    f.close();
    return  0;
}

int SoftLicense::getCpuidAndTimeFromFile(std::string &cpu_id, std::string &ctime)
{
    std::ifstream f;
    f.open(m_license_path,std::ios_base::binary | std::ios_base::in);
    if(!f.good())
    {
        //文件不存在
        qDebug() << "文件不存在" << m_license_path.c_str();
        return -1;
    }

    char *buff = new char[1024];
    memset(buff,0,1024);

    f.read((char*)buff,1024);

    int nCount = f.gcount();
    std::string strbuff;
    for(int i = 0;i < nCount;i++)
    {
        strbuff.push_back(buff[i]);
    }
    delete [] buff;
    std::string decstr = base64_decode(strbuff);

    uint8_t *ubuff = new uint8_t[decstr.length()];
    memset(ubuff,0,decstr.length());

    for(int i = 0;i < (int)decstr.length();i++)
    {
        ubuff[i] = decstr.at(i);
    }

    AES_ECB_decrypt(&m_ctx,ubuff);
    bool bcpuid = true;
    for(int i = 0; i < (int)decstr.length();i++)
    {
        if(ubuff[i] != MAKR_CHAR && bcpuid)
        {
            cpu_id.push_back(ubuff[i]);
        }
        if(ubuff[i] == MAKR_CHAR)
        {
            bcpuid = false;
            continue;
        }
        if(!bcpuid)
        {
            ctime.push_back(ubuff[i]);
        }

    }
    delete [] ubuff;
    return 0;
}


bool SoftLicense::isCpuidCurrectOrTimeisOver(const std::string &cpuid, const std::string &ctime)
{
    std::string curcpuid;
    if(!get_cpu_id(curcpuid))
    {
        return  false;
    }
    if(curcpuid != cpuid)
    {
        return false;
    }

    QDateTime qtime = QDateTime::currentDateTime();
    QDateTime cctime = QDateTime::fromString(ctime.c_str(),"yyyy-MM-dd");

    qint64 dtday = qtime.daysTo(cctime);
    if(dtday > DT_DAT)
    {
        return false;
    }
    return true;
}

bool SoftLicense::isCanUse()
{
    std::string s_cpuid;
    std::string s_time;
    if(-1 == getCpuidAndTimeFromFile(s_cpuid,s_time))
    {
        return false;
    }
    return isCpuidCurrectOrTimeisOver(s_cpuid,s_time);
}
bool SoftLicense::get_cpu_id_by_asm(std::string & cpu_id)
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

void SoftLicense::parse_cpu_id(const char * file_name, const char * match_words, std::string & cpu_id)
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

bool SoftLicense::get_cpu_id_by_system(std::string & cpu_id)
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

bool SoftLicense::get_cpu_id(std::string & cpu_id)
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


void SoftLicense::initaes()
{
    AES_init_ctx(&m_ctx, m_key);
}
