/* Copyright 2008 The Android Open Source Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "binder.h"

#define MAX_BIO_SIZE (1 << 30)

#define TRACE 0

#define LOG_TAG "Binder"
#include <cutils/log.h>

void bio_init_from_txn(struct binder_io *io, struct binder_txn *txn);

#if TRACE
void hexdump(void *_data, unsigned len)
{
    unsigned char *data = _data;
    unsigned count;

    for (count = 0; count < len; count++) {
        if ((count & 15) == 0)
            fprintf(stderr,"%04x:", count);
        fprintf(stderr," %02x %c", *data,
                (*data < 32) || (*data > 126) ? '.' : *data);
        data++;
        if ((count & 15) == 15)
            fprintf(stderr,"\n");
    }
    if ((count & 15) != 0)
        fprintf(stderr,"\n");
}

void binder_dump_txn(struct binder_txn *txn)
{
    struct binder_object *obj;
    unsigned *offs = txn->offs;
    unsigned count = txn->offs_size / 4;

    fprintf(stderr,"  target %p  cookie %p  code %08x  flags %08x\n",
            txn->target, txn->cookie, txn->code, txn->flags);
    fprintf(stderr,"  pid %8d  uid %8d  data %8d  offs %8d\n",
            txn->sender_pid, txn->sender_euid, txn->data_size, txn->offs_size);
    hexdump(txn->data, txn->data_size);
    while (count--) {
        obj = (void*) (((char*) txn->data) + *offs++);
        fprintf(stderr,"  - type %08x  flags %08x  ptr %p  cookie %p\n",
                obj->type, obj->flags, obj->pointer, obj->cookie);
    }
}

#define NAME(n) case n: return #n
const char *cmd_name(uint32_t cmd)
{
    switch(cmd) {
        NAME(BR_NOOP);
        NAME(BR_TRANSACTION_COMPLETE);
        NAME(BR_INCREFS);
        NAME(BR_ACQUIRE);
        NAME(BR_RELEASE);
        NAME(BR_DECREFS);
        NAME(BR_TRANSACTION);
        NAME(BR_REPLY);
        NAME(BR_FAILED_REPLY);
        NAME(BR_DEAD_REPLY);
        NAME(BR_DEAD_BINDER);
    default: return "???";
    }
}
#else
#define hexdump(a,b) do{} while (0)
#define binder_dump_txn(txn)  do{} while (0)
#endif

// 表示结构体binder_io内部的数据缓冲区是一块在内核空间分配的内核缓冲区
// 可以通过用户空间地址来共享访问
// 当使用完成这个数据缓冲区之后，它就可以使用BC_FREE_BUFFER命令协议来通知Binder驱动释放相应的内核缓冲区
#define BIO_F_SHARED    0x01  /* needs to be buffer freed */
// 表示两个错误码
//
// 表示数据溢出，上次读出的数据大小超出了其内部的数据缓冲区大小
#define BIO_F_OVERFLOW  0x02  /* ran out of space */
// 上次从结构体binder_io读数据时发生了IO错误
#define BIO_F_IOERROR   0x04
// binder_io内部的数据缓冲区是通过malloc来分配的
// 它指的是一块在用户空间分配的缓冲区
// 当进程完成这个数据缓冲区后，可以直接调用函数free释放
#define BIO_F_MALLOCED  0x08  /* needs to be free()'d */

// Service Manager打开了设备文件/dev/binder之后，就会得到文件描述符
struct binder_state
{
    // 文件描述符保存在变量fd中
    int fd;
    // 打开设备文件后，需要将设备文件映射到进程的地址空间，以便可以为驱动分配内核缓冲区来保存进程通信数据
    // servicemanager需要将设备文件/dev/binder映射到自己的进程地址空间
    //
    // 映射后的起始地址
    void *mapped;
    // 映射后的地址空间大小
    unsigned mapsize;
};

struct binder_state *binder_open(unsigned mapsize)
{
    struct binder_state *bs;

    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return 0;
    }

    // 打开设备文件
    bs->fd = open("/dev/binder", O_RDWR);
    if (bs->fd < 0) {
        fprintf(stderr,"binder: cannot open device (%s)\n",
                strerror(errno));
        goto fail_open;
    }

    // mapsize是128*1024=128K
    bs->mapsize = mapsize;
    // 请求分配128K的内核缓冲区
    // 映射后得到的地址空间起始地址和大小分别保存在binder_state->mapped和mapsize中
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        fprintf(stderr,"binder: cannot map device (%s)\n",
                strerror(errno));
        goto fail_map;
    }

        /* TODO: check version */

    return bs;

fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return 0;
}

void binder_close(struct binder_state *bs)
{
    munmap(bs->mapped, bs->mapsize);
    close(bs->fd);
    free(bs);
}

int binder_become_context_manager(struct binder_state *bs)
{
    return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);
}

int binder_write(struct binder_state *bs, void *data, unsigned len)
{
    struct binder_write_read bwr;
    int res;
    bwr.write_size = len;
    bwr.write_consumed = 0;
    bwr.write_buffer = (unsigned) data;
    // 输出缓冲区设置为空，当前线程将自己注册到Binder驱动后，就会马上返回用户空间
    // 不会在Binder驱动程序中等待Client
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    // 进行注册
    res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        fprintf(stderr,"binder_write: ioctl failed (%s)\n",
                strerror(errno));
    }
    return res;
}

// reply: binder_io结构体，内部包含了进程间通信结果数据
// buffer_to_free：用户空间地址，指向了一块用来传输进程间通信数据的内核缓冲区
// status: 用来描述servicemanager是否成功处理了一个进程间通信请求，即是否成功注册了service组件
void binder_send_reply(struct binder_state *bs,
                       struct binder_io *reply,
                       void *buffer_to_free,
                       int status)
{
    // 匿名结构体
    // 用来描述一个BC_FREE_BUFFER和一个BC_REPLY命令协议
    struct {
        uint32_t cmd_free;
        void *buffer;
        uint32_t cmd_reply;
        struct binder_txn txn;
    } __attribute__((packed)) data;

    // 设置匿名结构体data中的BC_FREE_BUFFER命令协议内容
    data.cmd_free = BC_FREE_BUFFER;
    data.buffer = buffer_to_free;
    data.cmd_reply = BC_REPLY;
    data.txn.target = 0;
    data.txn.cookie = 0;
    data.txn.code = 0;
    if (status) {
        data.txn.flags = TF_STATUS_CODE;
        data.txn.data_size = sizeof(int);
        data.txn.offs_size = 0;
        data.txn.data = &status;
        data.txn.offs = 0;
    } else {
        data.txn.flags = 0;
        data.txn.data_size = reply->data - reply->data0;
        data.txn.offs_size = ((char*) reply->offs) - ((char*) reply->offs0);
        data.txn.data = reply->data0;
        data.txn.offs = reply->offs0;
    }
    // 将BC_FREE_BUFFER和BC_REPLY命令协议发送给Binder驱动程序
    binder_write(bs, &data, sizeof(data));
}

// 处理从驱动接收到的返回协议
int binder_parse(struct binder_state *bs, struct binder_io *bio,
                 uint32_t *ptr, uint32_t size, binder_handler func)
{
    int r = 1;
    uint32_t *end = ptr + (size / 4);

    while (ptr < end) {
        // 读出返回协议码
        uint32_t cmd = *ptr++;
#if TRACE
        fprintf(stderr,"%s:\n", cmd_name(cmd));
#endif
        switch(cmd) {
        case BR_NOOP:
            break;
        case BR_TRANSACTION_COMPLETE:
            break;
        case BR_INCREFS:
        case BR_ACQUIRE:
        case BR_RELEASE:
        case BR_DECREFS:
#if TRACE
            fprintf(stderr,"  %08x %08x\n", ptr[0], ptr[1]);
#endif
            ptr += 2;
            break;
        case BR_TRANSACTION: {
            // 获取通信的数据
            struct binder_txn *txn = (void *) ptr;
            if ((end - ptr) * sizeof(uint32_t) < sizeof(struct binder_txn)) {
                LOGE("parse: txn too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (func) {
                unsigned rdata[256/4];
                // 定义两个binder_io结构体
                //
                // 用来解析从Binder驱动程序读取回来的进程间通信数据
                struct binder_io msg;
                // 用来将进程间通信结果数据保存到缓冲区rdata中，以便后面可以将它返回给Binder驱动程序
                struct binder_io reply;
                int res;

                // 分别使用函数bio_init, bio_init_from_txn来初始化
                bio_init(&reply, rdata, sizeof(rdata), 4);
                bio_init_from_txn(&msg, txn);
                // 调用func来处理保存在binder_io结构体msg中的BR_TRANSACTION返回协议
                // 将处理结果保存在binder_io结构体reply中
                //
                // func函数指针指向的是service manager进程中的函数svcmgr_handler
                res = func(bs, txn, &msg, &reply);
                // 将进程间的通信结果返回给Binder驱动
                binder_send_reply(bs, &reply, txn->data, res);
            }
            ptr += sizeof(*txn) / sizeof(uint32_t);
            break;
        }
        case BR_REPLY: {
            struct binder_txn *txn = (void*) ptr;
            if ((end - ptr) * sizeof(uint32_t) < sizeof(struct binder_txn)) {
                LOGE("parse: reply too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (bio) {
                bio_init_from_txn(bio, txn);
                bio = 0;
            } else {
                    /* todo FREE BUFFER */
            }
            ptr += (sizeof(*txn) / sizeof(uint32_t));
            r = 0;
            break;
        }
        case BR_DEAD_BINDER: {
            struct binder_death *death = (void*) *ptr++;
            death->func(bs, death->ptr);
            break;
        }
        case BR_FAILED_REPLY:
            r = -1;
            break;
        case BR_DEAD_REPLY:
            r = -1;
            break;
        default:
            LOGE("parse: OOPS %d\n", cmd);
            return -1;
        }
    }

    return r;
}

void binder_acquire(struct binder_state *bs, void *ptr)
{
    uint32_t cmd[2];
    cmd[0] = BC_ACQUIRE;
    cmd[1] = (uint32_t) ptr;
    binder_write(bs, cmd, sizeof(cmd));
}

void binder_release(struct binder_state *bs, void *ptr)
{
    uint32_t cmd[2];
    cmd[0] = BC_RELEASE;
    cmd[1] = (uint32_t) ptr;
    binder_write(bs, cmd, sizeof(cmd));
}

void binder_link_to_death(struct binder_state *bs, void *ptr, struct binder_death *death)
{
    uint32_t cmd[3];
    cmd[0] = BC_REQUEST_DEATH_NOTIFICATION;
    cmd[1] = (uint32_t) ptr;
    cmd[2] = (uint32_t) death;
    binder_write(bs, cmd, sizeof(cmd));
}


int binder_call(struct binder_state *bs,
                struct binder_io *msg, struct binder_io *reply,
                void *target, uint32_t code)
{
    int res;
    struct binder_write_read bwr;
    struct {
        uint32_t cmd;
        struct binder_txn txn;
    } writebuf;
    unsigned readbuf[32];

    if (msg->flags & BIO_F_OVERFLOW) {
        fprintf(stderr,"binder: txn buffer overflow\n");
        goto fail;
    }

    writebuf.cmd = BC_TRANSACTION;
    writebuf.txn.target = target;
    writebuf.txn.code = code;
    writebuf.txn.flags = 0;
    writebuf.txn.data_size = msg->data - msg->data0;
    writebuf.txn.offs_size = ((char*) msg->offs) - ((char*) msg->offs0);
    writebuf.txn.data = msg->data0;
    writebuf.txn.offs = msg->offs0;

    bwr.write_size = sizeof(writebuf);
    bwr.write_consumed = 0;
    bwr.write_buffer = (unsigned) &writebuf;
    
    hexdump(msg->data0, msg->data - msg->data0);
    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (unsigned) readbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            fprintf(stderr,"binder: ioctl failed (%s)\n", strerror(errno));
            goto fail;
        }

        res = binder_parse(bs, reply, readbuf, bwr.read_consumed, 0);
        if (res == 0) return 0;
        if (res < 0) goto fail;
    }

fail:
    memset(reply, 0, sizeof(*reply));
    reply->flags |= BIO_F_IOERROR;
    return -1;
}

// 由于service manager需要在系统运行期间为Service组件和Client组件提供服务
// 它就需要通过一个无限循环来等待和处理service和client的进程间通信请求
//
// bs: binder_open中创建的一个binder_state结构体
// func: 指向servicemanger函数svcmgr_handler, 用来处理service组件和client组件进程间通信请求
void binder_loop(struct binder_state *bs, binder_handler func)
{
    int res;
    struct binder_write_read bwr;
    unsigned readbuf[32];

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;
    
    // 通过BC_ENTER_LOOPER将自己注册到Binder驱动程序中
    readbuf[0] = BC_ENTER_LOOPER;
    // 调用binder_write将它发送到Binder驱动程序中
    binder_write(bs, readbuf, sizeof(unsigned));

    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (unsigned) readbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            LOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
            break;
        }

        // 如果有请求处理，会交给binder_parse来处理
        // 否则睡眠等待，直到有进程间通信请求来到为止
        res = binder_parse(bs, 0, readbuf, bwr.read_consumed, func);
        if (res == 0) {
            LOGE("binder_loop: unexpected reply?!\n");
            break;
        }
        if (res < 0) {
            LOGE("binder_loop: io error %d %s\n", res, strerror(errno));
            break;
        }
    }
}

// io: 要初始化的binder_io结构体
// txn: 包含了binder_io结构体要解析的数据缓冲区和偏移数组
void bio_init_from_txn(struct binder_io *bio, struct binder_txn *txn)
{
    bio->data = bio->data0 = txn->data;
    bio->offs = bio->offs0 = txn->offs;
    bio->data_avail = txn->data_size;
    bio->offs_avail = txn->offs_size / 4;
    // 设置flag, 表示内部的数据缓冲区和偏移数组是在内核空间分配的
    bio->flags = BIO_F_SHARED;
}

// bio: 要初始化的binder_io结构体
// data: bio内部所用的缓冲区
// maxdata: 用来描述缓冲区data的大小
// maxoffs: 描述bio内部的偏移数组大小
void bio_init(struct binder_io *bio, void *data,
              uint32_t maxdata, uint32_t maxoffs)
{
    uint32_t n = maxoffs * sizeof(uint32_t);

    // 判断是否大于缓冲区data的大小
    if (n > maxdata) {
        bio->flags = BIO_F_OVERFLOW;
        bio->data_avail = 0;
        bio->offs_avail = 0;
        return;
    }

    // 将data分成了两部分
    //
    // 一部分用于binder_io结构体bio的数据缓冲区
    // 另一部分用户binder_io结构体的bio偏移数组
    bio->data = bio->data0 = data + n;
    bio->offs = bio->offs0 = data;
    // 设置可用的数据缓冲区和偏移数组的大小
    bio->data_avail = maxdata - n;
    bio->offs_avail = maxoffs;
    bio->flags = 0;
}

static void *bio_alloc(struct binder_io *bio, uint32_t size)
{
    size = (size + 3) & (~3);
    if (size > bio->data_avail) {
        bio->flags |= BIO_F_OVERFLOW;
        return 0;
    } else {
        void *ptr = bio->data;
        bio->data += size;
        bio->data_avail -= size;
        return ptr;
    }
}

void binder_done(struct binder_state *bs,
                 struct binder_io *msg,
                 struct binder_io *reply)
{
    if (reply->flags & BIO_F_SHARED) {
        uint32_t cmd[2];
        cmd[0] = BC_FREE_BUFFER;
        cmd[1] = (uint32_t) reply->data0;
        binder_write(bs, cmd, sizeof(cmd));
        reply->flags = 0;
    }
}

static struct binder_object *bio_alloc_obj(struct binder_io *bio)
{
    struct binder_object *obj;

    obj = bio_alloc(bio, sizeof(*obj));
    
    if (obj && bio->offs_avail) {
        bio->offs_avail--;
        *bio->offs++ = ((char*) obj) - ((char*) bio->data0);
        return obj;
    }

    bio->flags |= BIO_F_OVERFLOW;
    return 0;
}

void bio_put_uint32(struct binder_io *bio, uint32_t n)
{
    uint32_t *ptr = bio_alloc(bio, sizeof(n));
    if (ptr)
        *ptr = n;
}

void bio_put_obj(struct binder_io *bio, void *ptr)
{
    struct binder_object *obj;

    obj = bio_alloc_obj(bio);
    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->type = BINDER_TYPE_BINDER;
    obj->pointer = ptr;
    obj->cookie = 0;
}

void bio_put_ref(struct binder_io *bio, void *ptr)
{
    struct binder_object *obj;

    if (ptr)
        obj = bio_alloc_obj(bio);
    else
        obj = bio_alloc(bio, sizeof(*obj));

    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->type = BINDER_TYPE_HANDLE;
    obj->pointer = ptr;
    obj->cookie = 0;
}

void bio_put_string16(struct binder_io *bio, const uint16_t *str)
{
    uint32_t len;
    uint16_t *ptr;

    if (!str) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    len = 0;
    while (str[len]) len++;

    if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    bio_put_uint32(bio, len);
    len = (len + 1) * sizeof(uint16_t);
    ptr = bio_alloc(bio, len);
    if (ptr)
        memcpy(ptr, str, len);
}

void bio_put_string16_x(struct binder_io *bio, const char *_str)
{
    unsigned char *str = (unsigned char*) _str;
    uint32_t len;
    uint16_t *ptr;

    if (!str) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    len = strlen(_str);

    if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    bio_put_uint32(bio, len);
    ptr = bio_alloc(bio, (len + 1) * sizeof(uint16_t));
    if (!ptr)
        return;

    while (*str)
        *ptr++ = *str++;
    *ptr++ = 0;
}

static void *bio_get(struct binder_io *bio, uint32_t size)
{
    // 将它对齐到4个字节边界
    size = (size + 3) & (~3);

    // 剩余的为解析字节数data_avail是否小于要求读取的字节数size
    if (bio->data_avail < size){
        bio->data_avail = 0;
        // 如果是，那么就是溢出了
        bio->flags |= BIO_F_OVERFLOW;
        return 0;
    }  else {
        // 如果否，将data当前的位置保存在ptr中
        void *ptr = bio->data;
        // 往前推进size个字节
        bio->data += size;
        // 未读取的字节数减少size个字节
        bio->data_avail -= size;
        return ptr;
    }
}

uint32_t bio_get_uint32(struct binder_io *bio)
{
    uint32_t *ptr = bio_get(bio, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint16_t *bio_get_string16(struct binder_io *bio, unsigned *sz)
{
    unsigned len;
    len = bio_get_uint32(bio);
    if (sz)
        *sz = len;
    return bio_get(bio, (len + 1) * sizeof(uint16_t));
}

static struct binder_object *_bio_get_obj(struct binder_io *bio)
{
    unsigned n;
    unsigned off = bio->data - bio->data0;

        /* TODO: be smarter about this? */
    // 循环检查binder_io结构体的数据缓冲区当前位置是否保存了一个binder_object结构体
    for (n = 0; n < bio->offs_avail; n++) {
        if (bio->offs[n] == off)
            return bio_get(bio, sizeof(struct binder_object));
    }

    bio->data_avail = 0;
    bio->flags |= BIO_F_OVERFLOW;
    return 0;
}

void *bio_get_ref(struct binder_io *bio)
{
    // 从binder_io结构体取出一个binder_object结构体
    struct binder_object *obj;

    obj = _bio_get_obj(bio);
    if (!obj)
        return 0;

    if (obj->type == BINDER_TYPE_HANDLE)
        // 将成员变量pointer返回，pointer保存的是一个由Binder驱动程序创建的引用对象的句柄值
        // 这个引用对象引用了即将要注册的Service组件
        return obj->pointer;

    return 0;
}
