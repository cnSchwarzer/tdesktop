#include "secgram.hpp"
#include "SecgramCore.hpp"

static Secgram *instance;

Secgram *Secgram::me() { return instance; }

Secgram *Secgram::init(std::string pwd, std::string path) { 
    instance = new Secgram();
    instance->core = new SecgramCore(pwd, path);
    return instance;
}
