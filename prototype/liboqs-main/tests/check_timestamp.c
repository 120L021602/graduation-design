#include "check_timestamp.h"

bool CheckTimestamp(uint64_t timestamp){
    
    // 获取当前时间的 UNIX 时间戳
    time_t currentTime = time(NULL);

    // 将 time_t 类型的时间戳转换为 uint64_t 类型
    uint64_t currentTimeUint64 = (uint64_t)currentTime;

    // 若时间间隔小于1秒，则通过
    if((currentTimeUint64 - timestamp) < 1){
        return true;
    }

    return false;
}