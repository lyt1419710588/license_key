/*
 * @brief
 * 生成软件保护文件，绑定电脑CPUID
 * 无许可文件，使其不能运行
*/
#ifndef SOFTLICENSE_H
#define SOFTLICENSE_H

#include "aes.hpp"
#include "base64.h"
#include <arpa/inet.h>
#include <fstream>
#include <unistd.h>
#include <cstring>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <QDateTime>

#define M_KEY_LEN 16
#define LICENSE_PATH "license.key";
#define MAKR_CHAR '&'
const int DT_DAT = 30;

class SoftLicense
{
public:
    SoftLicense();

//获取cpuid方法
public:
    static bool get_cpu_id_by_asm(std::string & cpu_id);
    static void parse_cpu_id(const char * file_name, const char * match_words, std::string & cpu_id);
    static bool get_cpu_id_by_system(std::string & cpu_id);
    static bool get_cpu_id(std::string & cpu_id);

    //生存license.key文件
public:
    /*
     * @brief
     * 设置AES,KEY
     * 该方法一般不允许被调用
    */
    int setAesKey(uint8_t* key,int nlen);

    /*
     * @brief
     * strbuf 要加密的字符串
     * 加上&日期，再加密
     * @rtl
     * 返回值，经过base64编码后的ase加密字符串
    */
    std::string getAesBase64Str(const std::string& strbuff);

protected:
    /*
     * @brief
     * 写加密后的字符串到文件
    */
    int writeAesBase64StrToFile(const std::string &strbuff,const std::string& fullpath);

    //license.key文件读取，判断合法性
public:
    /*
     * @brief
     * 判断软件使用是否合法
     *
     * 不合法：过期或者cpuid未被认证
    */
    bool isCanUse();
protected:
    /*
     * @brief
     * 从key文件中读取加密字符串，解密出时间和cpu_id
    */
    int getCpuidAndTimeFromFile(std::string& cpu_id,std::string& ctime);

    /*
     * @brief
     * 判断本机cpuid和加密文本中解析出的cpuid是否相同，时间是否过期
    */
    bool isCpuidCurrectOrTimeisOver(const std::string& cpuid,const std::string& ctime);
protected:
    void initaes();
private:
    //aes加密用到key
    uint8_t m_key[M_KEY_LEN];
    //AES上下文
    struct AES_ctx m_ctx;
    //license文件生成路径
    std::string m_license_path;
};

#endif // SOFTLICENSE_H
