#pragma once

#include <string>

class SecgramCore;
class Secgram {
    SecgramCore* core;
  public:
    static Secgram *init(std::string pwd, std::string path);
    static Secgram *me();
};
