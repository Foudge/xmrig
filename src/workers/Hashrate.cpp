/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2016-2017 XMRig       <support@xmrig.com>
 *
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include <chrono>
#include <math.h>
#include <memory.h>
#include <stdio.h>

#include "log/Log.h"
#include "Options.h"
#include "workers/Hashrate.h"


inline const char *format(double h, char* buf, size_t size)
{
    if (isnormal(h)) {
        snprintf(buf, size, "%03.1f", h);
        return buf;
    }

    return "n/a";
}


Hashrate::Hashrate(int threads) :
    m_highest(0.0),
    m_average(0.0),
    m_threads(threads)
{
    m_counts     = new uint64_t*[threads];
    m_timestamps = new uint64_t*[threads];
    m_top        = new uint32_t[threads];

    for (int i = 0; i < threads; i++) {
        m_counts[i] = new uint64_t[kBucketSize + 1];
        m_timestamps[i] = new uint64_t[kBucketSize + 1];
        m_top[i] = 0;

        memset(m_counts[i], 0, sizeof(uint64_t) * (kBucketSize + 1));
        memset(m_timestamps[i], 0, sizeof(uint64_t) * (kBucketSize + 1));
    }

    const int printTime = Options::i()->printTime();

    if (printTime > 0) {
        uv_timer_init(uv_default_loop(), &m_timer);
        m_timer.data = this;

       uv_timer_start(&m_timer, Hashrate::onReport, (printTime + 4) * 1000, printTime * 1000);
    }
}


double Hashrate::calc(size_t ms) const
{
    double result = 0.0;
    double data;

    for (int i = 0; i < m_threads; ++i) {
        data = calc(i, ms);
        if (isnormal(data))
            result += data;
    }

    return result;
}


double Hashrate::calc(size_t threadId, size_t ms) const
{
    using namespace std::chrono;
    const uint64_t now = time_point_cast<milliseconds>(high_resolution_clock::now()).time_since_epoch().count();

    uint64_t earliestHashCount = 0;
    uint64_t earliestStamp     = 0;
    uint64_t lastestStamp      = 0;
    uint64_t lastestHashCnt    = 0;

    for (size_t i = 1; i < kBucketSize; i++) {
        const size_t idx = (m_top[threadId] - i) & kBucketMask;

        if (m_timestamps[threadId][idx] == 0) {
            break;
        }

        if (lastestStamp == 0) {
            lastestStamp = m_timestamps[threadId][idx];
            lastestHashCnt = m_counts[threadId][idx];
        }
        else {
            if (now - m_timestamps[threadId][idx] > ms) {
                earliestStamp = m_timestamps[threadId][idx];
                earliestHashCount = m_counts[threadId][idx];
                break;
            }
        }
    }

    if (earliestStamp == 0 || lastestStamp == 0) {
        return nan("");
    }

    if (lastestStamp == earliestStamp) {
        return nan("");
    }

    double hashes, time;
    hashes = (double) lastestHashCnt - earliestHashCount;
    time   = (double) lastestStamp - earliestStamp;
    time  /= 1000.0;

    return hashes / time;
}


void Hashrate::add(size_t threadId, uint64_t count, uint64_t timestamp)
{
    const size_t top = m_top[threadId];
    m_counts[threadId][top]     = count;
    m_timestamps[threadId][top] = timestamp;

    if (m_timestamps[threadId][kBucketSize] == 0 && count > 0) {
        m_timestamps[threadId][kBucketSize] = timestamp;
        m_counts[threadId][kBucketSize] = count;
    }

    m_top[threadId] = (top + 1) & kBucketMask;
}


void Hashrate::print()
{
    char num1[8], num2[8], num3[8];
    double shortHashrate = calc(ShortInterval);
    updateHighest(shortHashrate);
    updateAverage();

    LOG_INFO(Options::i()->colors() ? "\x1B[01;37mspeed (H/s)  \x1B[0mcurrent \x1B[01;36m%s  \x1B[0mavg \x1B[01;36m%s  \x1B[0mmax \x1B[22;36m%s" : "speed (H/s)  current %s  avg %s  max %s",
             format(shortHashrate,  num1, sizeof(num1)),
             format(m_average,      num2, sizeof(num2)),
             format(m_highest,      num3, sizeof(num3))
             );
}


void Hashrate::stop()
{
    uv_timer_stop(&m_timer);
}


void Hashrate::updateHighest()
{
   updateHighest(calc(ShortInterval));
}


void Hashrate::updateHighest(double hashrate)
{
    if (isnormal(hashrate) && hashrate > m_highest) {
        m_highest = hashrate;
    }
}


void Hashrate::updateAverage()
{
    double result = 0.0;
    uint64_t hashes, t1, t2;
    size_t idx = 0;

    for (int i = 0; i < m_threads; ++i) {
        idx = (m_top[i] - 1) & kBucketMask;
        t1 = m_timestamps[i][kBucketSize];
        t2 = m_timestamps[i][idx];
        if (t1 && t2 && t1 < t2 ) {
            hashes = m_counts[i][idx] - m_counts[i][kBucketSize];
            result += ((double)hashes / ((double)(t2 - t1) / 1000.0));
        }
        else {
            result = nan("");
            break;
        }
    }

    if (isnormal(result))
        m_average = result;
}


void Hashrate::onReport(uv_timer_t *handle)
{
    static_cast<Hashrate*>(handle->data)->print();
}
