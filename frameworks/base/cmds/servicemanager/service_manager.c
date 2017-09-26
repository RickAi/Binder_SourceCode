/* Copyright 2008 The Android Open Source Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <private/android_filesystem_config.h>

#include "binder.h"

#if 0
#define LOGI(x...) fprintf(stderr, "svcmgr: " x)
#define LOGE(x...) fprintf(stderr, "svcmgr: " x)
#else
#define LOG_TAG "ServiceManager"
#include <cutils/log.h>
#endif

/* TODO:
 * These should come from a config file or perhaps be
 * based on some namespace rules of some sort (media
 * uid can register media.*, etc)
 */
static struct {
    unsigned uid;
    const char *name;
} allowed[] = {
#ifdef LVMX
    // 用户名为uid的进程才能注册名为xxx的service组件
    { AID_MEDIA, "com.lifevibes.mx.ipc" },
#endif
    { AID_MEDIA, "media.audio_flinger" },
    { AID_MEDIA, "media.player" },
    { AID_MEDIA, "media.camera" },
    { AID_MEDIA, "media.audio_policy" },
    { AID_DRMIO, "drm.drmIOService" },
    { AID_DRM,   "drm.drmManager" },
    { AID_NFC,   "nfc" },
    { AID_RADIO, "radio.phone" },
    { AID_RADIO, "radio.sms" },
    { AID_RADIO, "radio.phonesubinfo" },
    { AID_RADIO, "radio.simphonebook" },
/* TODO: remove after phone services are updated: */
    { AID_RADIO, "phone" },
    { AID_RADIO, "sip" },
    { AID_RADIO, "isms" },
    { AID_RADIO, "iphonesubinfo" },
    { AID_RADIO, "simphonebook" },
};

void *svcmgr_handle;

const char *str8(uint16_t *x)
{
    static char buf[128];
    unsigned max = 127;
    char *p = buf;

    if (x) {
        while (*x && max--) {
            *p++ = *x++;
        }
    }
    *p++ = 0;
    return buf;
}

int str16eq(uint16_t *a, const char *b)
{
    while (*a && *b)
        if (*a++ != *b++) return 0;
    if (*a || *b)
        return 0;
    return 1;
}

// 注册service是一种特权，不是所有进程都可以将service组件注册到service manager中
int svc_can_register(unsigned uid, uint16_t *name)
{
    unsigned n;
    
    // 如果发现用户id是系统进程或是AID_SYSTEM进程，将不受限制
    if ((uid == 0) || (uid == AID_SYSTEM))
        return 1;

    // allowed是一个全局的数组，定义了可以注册什么名称的service组件
    for (n = 0; n < sizeof(allowed) / sizeof(allowed[0]); n++)
        if ((uid == allowed[n].uid) && str16eq(name, allowed[n].name))
            return 1;

    return 0;
}

struct svcinfo 
{
    // 描述下一个svcinfo结构体
    struct svcinfo *next;
    // 句柄值，描述注册了的service组件
    void *ptr;
    // 死亡通知
    struct binder_death death;
    // 长度
    unsigned len;
    // 已经注册了的service组件名称
    uint16_t name[0];
};

// 每一个被注册了的service组件都使用了svcinfo结构体来描述
// 保存在一个全局队列svclist中
struct svcinfo *svclist = 0;

struct svcinfo *find_svc(uint16_t *s16, unsigned len)
{
    struct svcinfo *si;

    // 循环检查全局队列svclist中已注册service组件列表
    for (si = svclist; si; si = si->next) {
        if ((len == si->len) &&
            // 发现已经存在的话会将s16对应的svcinfo结构体返回给调用者
            !memcmp(s16, si->name, len * sizeof(uint16_t))) {
            return si;
        }
    }
    return 0;
}

void svcinfo_death(struct binder_state *bs, void *ptr)
{
    struct svcinfo *si = ptr;
    LOGI("service '%s' died\n", str8(si->name));
    if (si->ptr) {
        binder_release(bs, si->ptr);
        si->ptr = 0;
    }   
}

uint16_t svcmgr_id[] = { 
    'a','n','d','r','o','i','d','.','o','s','.',
    'I','S','e','r','v','i','c','e','M','a','n','a','g','e','r' 
};
  

void *do_find_service(struct binder_state *bs, uint16_t *s, unsigned len)
{
    struct svcinfo *si;
    si = find_svc(s, len);

//    LOGI("check_service('%s') ptr = %p\n", str8(s), si ? si->ptr : 0);
    if (si && si->ptr) {
        return si->ptr;
    } else {
        return 0;
    }
}

int do_add_service(struct binder_state *bs,
                   uint16_t *s, unsigned len,
                   void *ptr, unsigned uid)
{
    struct svcinfo *si;
//    LOGI("add_service('%s',%p) uid=%d\n", str8(s), ptr, uid);

    if (!ptr || (len == 0) || (len > 127))
        return -1;

    // s: 要注册的service组件名称
    // uid: 注册service组件的进程的用户id
    //
    // 检查权限
    if (!svc_can_register(uid, s)) {
        LOGE("add_service('%s',%p) uid=%d - PERMISSION DENIED\n",
             str8(s), ptr, uid);
        return -1;
    }

    // 检查是否已经注册过
    si = find_svc(s, len);
    if (si) {
        if (si->ptr) {
            // 已经被使用过
            LOGE("add_service('%s',%p) uid=%d - ALREADY REGISTERED\n",
                 str8(s), ptr, uid);
            return -1;
        }
        // 修改ptr参数
        si->ptr = ptr;
    } else {
        // 如果没有被引用，就会创建一个svcinfo结构体来描述要注册的service组件
        si = malloc(sizeof(*si) + (len + 1) * sizeof(uint16_t));
        if (!si) {
            LOGE("add_service('%s',%p) uid=%d - OUT OF MEMORY\n",
                 str8(s), ptr, uid);
            return -1;
        }
        si->ptr = ptr;
        si->len = len;
        memcpy(si->name, s, (len + 1) * sizeof(uint16_t));
        si->name[len] = '\0';
        si->death.func = svcinfo_death;
        si->death.ptr = si;
        si->next = svclist;
        // 添加到全局的svclist中
        svclist = si;
    }

    // 因为引用了新注册的service组件，因此需要调用binder_acquire来增加相应的binder引用对象的引用计数值
    binder_acquire(bs, ptr);
    // 注册一个Binder本地对象的死亡接收通知，以便service manager在该service组件死亡时采取相应的处理措施
    binder_link_to_death(bs, ptr, &si->death);
    return 0;
}

int svcmgr_handler(struct binder_state *bs,
                   struct binder_txn *txn,
                   struct binder_io *msg,
                   struct binder_io *reply)
{
    struct svcinfo *si;
    uint16_t *s;
    unsigned len;
    void *ptr;
    uint32_t strict_policy;

//    LOGI("target=%p code=%d pid=%d uid=%d\n",
//         txn->target, txn->code, txn->sender_pid, txn->sender_euid);

    // 检查从驱动传进来的目标Binder本地对象是否指向在service manager中定义的虚拟Binder本地对象svcmgr_handle
    if (txn->target != svcmgr_handle)
        return -1;

    // Equivalent to Parcel::enforceInterface(), reading the RPC
    // header with the strict mode policy mask and the interface name.
    // Note that we ignore the strict_policy and don't propagate it
    // further (since we do no outbound RPCs anyway).
    // 检查Binder进程间通信请求头是否合法
    strict_policy = bio_get_uint32(msg);
    s = bio_get_string16(msg, &len);
    // 验证传递过来的服务接口描述符是否等于svcmgr_id
    if ((len != (sizeof(svcmgr_id) / 2)) ||
        memcmp(svcmgr_id, s, sizeof(svcmgr_id))) {
        // 如果不相等，说明这是一个非法的进程间通信请求
        fprintf(stderr,"invalid id %s\n", str8(s));
        return -1;
    }

    switch(txn->code) {
    case SVC_MGR_GET_SERVICE:
    case SVC_MGR_CHECK_SERVICE:
        s = bio_get_string16(msg, &len);
        ptr = do_find_service(bs, s, len);
        if (!ptr)
            break;
        bio_put_ref(reply, ptr);
        return 0;

    case SVC_MGR_ADD_SERVICE:
        s = bio_get_string16(msg, &len);
        // 从binder_io结构体中的数据缓冲区获取一个Binder引用对象的句柄值
        // 它引用了要注册的Service组件
        ptr = bio_get_ref(msg);
        if (do_add_service(bs, s, len, ptr, txn->sender_euid))
            return -1;
        break;

    case SVC_MGR_LIST_SERVICES: {
        unsigned n = bio_get_uint32(msg);

        si = svclist;
        while ((n-- > 0) && si)
            si = si->next;
        if (si) {
            bio_put_string16(reply, si->name);
            return 0;
        }
        return -1;
    }
    default:
        LOGE("unknown code %d\n", txn->code);
        return -1;
    }

    // 将注册成功的代码0写入到reply中
    // 返回给请求注册service组件的进程
    bio_put_uint32(reply, 0);
    return 0;
}

// Service Manager 是Binder进程间通信机制的核心组件之一，它扮演着进程间机制上下文管理者的角色
// 负责管理系统中Service组件，并且向Client组件提供获取Service代理对象的服务
// Service Manager运行在一个独立的进程中
// Service组件通常和Client组件也需要通过进程间通信机制来和它交互
// 采用的进程间通信机制正好也是Binder进程间通信机制
// ServiceManager是由init进程负责启动的
// 因此，ServiceManager也是在系统启动时启动的
int main(int argc, char **argv)
{
    struct binder_state *bs;
    void *svcmgr = BINDER_SERVICE_MANAGER;

    // 调用函数打开设备文件/dev/binder，将它映射到本进程的地址空间
    bs = binder_open(128*1024);

    // 将自己注册为Binder进程间通信机制的上下文管理者
    if (binder_become_context_manager(bs)) {
        LOGE("cannot become context manager (%s)\n", strerror(errno));
        return -1;
    }

    svcmgr_handle = svcmgr;
    // 循环等待和处理Client进程的通信
    binder_loop(bs, svcmgr_handler);
    return 0;
}
