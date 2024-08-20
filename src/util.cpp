#include "../include/util.h"
#include "../include/mac.h"
#include "../include/ip.h"
#include "../include/received_packet.h"

using namespace std;

string trim(const string &str)
{
    auto start = str.begin();
    while (start != str.end() && isspace(*start)) start++;

    auto end = str.end();
    do {
        end--;
    } while (distance(start, end) > 0 && isspace(*end));

    return string(start, end + 1);
}

string get_my_mac(const string &interface) {
    string cmd = "ifconfig "+interface+" | grep ether | awk -F \" \" \'{print $2}\'";
    string result = "";
    regex pattern(R"(^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$)");
    char buf[128];

    shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw runtime_error("[*] popen() failed!");

    while (fgets(buf, sizeof(buf), pipe.get()) != nullptr) result += buf;
    result = trim(result);

    if (result.length() != 17 || !regex_match(result, pattern))
        throw runtime_error("Can't get " + interface + " MAC address! Check your network connection or interface.");

    return result;
}

string get_my_ip(const string &interface) {
    string cmd = "ifconfig " + interface + " | grep \'inet \' | awk -F \" \" \'{print $2}\'";
    string result = "";
    regex pattern(R"(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)");
    char buf[128];

    shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw runtime_error("popen() failed!");

    while (fgets(buf, sizeof(buf), pipe.get()) != nullptr) result += buf;
    result = trim(result);

    if (!regex_match(result, pattern))
        throw runtime_error("Can't read ip address! Check your network connection or interface.");

    return result;
}
