/*
 * Copyright (C) 2005 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "BpBinder"
//#define LOG_NDEBUG 0

#include <binder/BpBinder.h>

#include <binder/IPCThreadState.h>
#include <utils/Log.h>

#include <stdio.h>

//#undef LOGV
//#define LOGV(...) fprintf(stderr, __VA_ARGS__)

namespace android {

// ---------------------------------------------------------------------------

BpBinder::ObjectManager::ObjectManager()
{
}

BpBinder::ObjectManager::~ObjectManager()
{
    kill();
}

void BpBinder::ObjectManager::attach(
    const void* objectID, void* object, void* cleanupCookie,
    IBinder::object_cleanup_func func)
{
    entry_t e;
    e.object = object;
    e.cleanupCookie = cleanupCookie;
    e.func = func;

    if (mObjects.indexOfKey(objectID) >= 0) {
        LOGE("Trying to attach object ID %p to binder ObjectManager %p with object %p, but object ID already in use",
                objectID, this,  object);
        return;
    }

    mObjects.add(objectID, e);
}

void* BpBinder::ObjectManager::find(const void* objectID) const
{
    const ssize_t i = mObjects.indexOfKey(objectID);
    if (i < 0) return NULL;
    return mObjects.valueAt(i).object;
}

void BpBinder::ObjectManager::detach(const void* objectID)
{
    mObjects.removeItem(objectID);
}

void BpBinder::ObjectManager::kill()
{
    const size_t N = mObjects.size();
    LOGV("Killing %d objects in manager %p", N, this);
    for (size_t i=0; i<N; i++) {
        const entry_t& e = mObjects.valueAt(i);
        if (e.func != NULL) {
            e.func(mObjects.keyAt(i), e.object, e.cleanupCookie);
        }
    }

    mObjects.clear();
}

// ---------------------------------------------------------------------------

// Binder代理对象是一个类型为BpBinder的对象，它是在用户空间中创建的
// 运行在Client进程中
// 与Binder本地对象类似，Binder代理对象一方面会被运行在Client进程中的其他对象引用
// 一方面它也会引用Binder驱动程序中的Binder引用对象
// BpBinder继承了RefBase类
// 其它对象可以通过智能指针来引用这些代理对象，以便控制它们的生命周期
// Binder驱动程序中的Binder引用对象是运行在内核空间中的，Binder代理对象不能通过智能指针来引用它们
// 需要通过四个协议来引用Binder驱动中的Binder引用对象
//
// 每一个Binder代理对象都是通过一个句柄值来和一个Binder引用对象关联的
// Client进程通过这个句柄值来维护运行在它里面的Binder代理对象
// 通常，Client进程会在内部建立一个handle_entry类型的Binder代理对象列表
// 以句柄值作为关键字来维护它内部所有的Binder代理对象
//
// 结构体内部有一个IBinder指针，指向一个BpBinder对象，即代理对象
// 每当Client代理对象列表中检查是否已经存在对应的handle_entry结构体
// 如果存在，那么Client进程就会使用该handle_entry结构体内部的IBinder指针所指向的BpBinder对象来和Server进程通信
// 如果不存在,Client进程就会先创建一个BpBinder对象，并且将它保存在handle_entry结构体中
// 以及handle_entry结构体保存在内部Binder代理对象列表中
// 这样做的好处是可以避免创建重复的Binder代理对象来引用Binder驱动中的同一个Binder引用对象
// 每一个Binder代理对象在创建时都会增加对应的Binder引用对象的引用计数
BpBinder::BpBinder(int32_t handle)
    : mHandle(handle)
    , mAlive(1)
    , mObitsSent(0)
    , mObituaries(NULL)
{
    LOGV("Creating BpBinder %p handle %d\n", this, mHandle);

    // 设置Binder代理对象的生命周期受到弱引用计数的影响
    extendObjectLifetime(OBJECT_LIFETIME_WEAK);
    // 调用当前线程内部的IPCThreadState对象的成员函数来增加相应的Binder引用对象的弱引用计数
    IPCThreadState::self()->incWeakHandle(handle);
}

bool BpBinder::isDescriptorCached() const {
    Mutex::Autolock _l(mLock);
    return mDescriptorCache.size() ? true : false;
}

const String16& BpBinder::getInterfaceDescriptor() const
{
    if (isDescriptorCached() == false) {
        Parcel send, reply;
        // do the IPC without a lock held.
        status_t err = const_cast<BpBinder*>(this)->transact(
                INTERFACE_TRANSACTION, send, &reply);
        if (err == NO_ERROR) {
            String16 res(reply.readString16());
            Mutex::Autolock _l(mLock);
            // mDescriptorCache could have been assigned while the lock was
            // released.
            if (mDescriptorCache.size() == 0)
                mDescriptorCache = res;
        }
    }
    
    // we're returning a reference to a non-static object here. Usually this
    // is not something smart to do, however, with binder objects it is 
    // (usually) safe because they are reference-counted.
    
    return mDescriptorCache;
}

bool BpBinder::isBinderAlive() const
{
    return mAlive != 0;
}

status_t BpBinder::pingBinder()
{
    Parcel send;
    Parcel reply;
    status_t err = transact(PING_TRANSACTION, send, &reply);
    if (err != NO_ERROR) return err;
    if (reply.dataSize() < sizeof(status_t)) return NOT_ENOUGH_DATA;
    return (status_t)reply.readInt32();
}

status_t BpBinder::dump(int fd, const Vector<String16>& args)
{
    Parcel send;
    Parcel reply;
    send.writeFileDescriptor(fd);
    const size_t numArgs = args.size();
    send.writeInt32(numArgs);
    for (size_t i = 0; i < numArgs; i++) {
        send.writeString16(args[i]);
    }
    status_t err = transact(DUMP_TRANSACTION, send, &reply);
    return err;
}

status_t BpBinder::transact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    // Once a binder has died, it will never come back to life.
    if (mAlive) {
        status_t status = IPCThreadState::self()->transact(
            mHandle, code, data, reply, flags);
        if (status == DEAD_OBJECT) mAlive = 0;
        return status;
    }

    return DEAD_OBJECT;
}

status_t BpBinder::linkToDeath(
    const sp<DeathRecipient>& recipient, void* cookie, uint32_t flags)
{
    Obituary ob;
    ob.recipient = recipient;
    ob.cookie = cookie;
    ob.flags = flags;

    LOG_ALWAYS_FATAL_IF(recipient == NULL,
                        "linkToDeath(): recipient must be non-NULL");

    {
        AutoMutex _l(mLock);

        if (!mObitsSent) {
            if (!mObituaries) {
                mObituaries = new Vector<Obituary>;
                if (!mObituaries) {
                    return NO_MEMORY;
                }
                LOGV("Requesting death notification: %p handle %d\n", this, mHandle);
                getWeakRefs()->incWeak(this);
                IPCThreadState* self = IPCThreadState::self();
                self->requestDeathNotification(mHandle, this);
                self->flushCommands();
            }
            ssize_t res = mObituaries->add(ob);
            return res >= (ssize_t)NO_ERROR ? (status_t)NO_ERROR : res;
        }
    }

    return DEAD_OBJECT;
}

status_t BpBinder::unlinkToDeath(
    const wp<DeathRecipient>& recipient, void* cookie, uint32_t flags,
    wp<DeathRecipient>* outRecipient)
{
    AutoMutex _l(mLock);

    if (mObitsSent) {
        return DEAD_OBJECT;
    }

    const size_t N = mObituaries ? mObituaries->size() : 0;
    for (size_t i=0; i<N; i++) {
        const Obituary& obit = mObituaries->itemAt(i);
        if ((obit.recipient == recipient
                    || (recipient == NULL && obit.cookie == cookie))
                && obit.flags == flags) {
            const uint32_t allFlags = obit.flags|flags;
            if (outRecipient != NULL) {
                *outRecipient = mObituaries->itemAt(i).recipient;
            }
            mObituaries->removeAt(i);
            if (mObituaries->size() == 0) {
                LOGV("Clearing death notification: %p handle %d\n", this, mHandle);
                IPCThreadState* self = IPCThreadState::self();
                self->clearDeathNotification(mHandle, this);
                self->flushCommands();
                delete mObituaries;
                mObituaries = NULL;
            }
            return NO_ERROR;
        }
    }

    return NAME_NOT_FOUND;
}

void BpBinder::sendObituary()
{
    LOGV("Sending obituary for proxy %p handle %d, mObitsSent=%s\n",
        this, mHandle, mObitsSent ? "true" : "false");

    mAlive = 0;
    if (mObitsSent) return;

    mLock.lock();
    Vector<Obituary>* obits = mObituaries;
    if(obits != NULL) {
        LOGV("Clearing sent death notification: %p handle %d\n", this, mHandle);
        IPCThreadState* self = IPCThreadState::self();
        self->clearDeathNotification(mHandle, this);
        self->flushCommands();
        mObituaries = NULL;
    }
    mObitsSent = 1;
    mLock.unlock();

    LOGV("Reporting death of proxy %p for %d recipients\n",
        this, obits ? obits->size() : 0);

    if (obits != NULL) {
        const size_t N = obits->size();
        for (size_t i=0; i<N; i++) {
            reportOneDeath(obits->itemAt(i));
        }

        delete obits;
    }
}

void BpBinder::reportOneDeath(const Obituary& obit)
{
    sp<DeathRecipient> recipient = obit.recipient.promote();
    LOGV("Reporting death to recipient: %p\n", recipient.get());
    if (recipient == NULL) return;

    recipient->binderDied(this);
}


void BpBinder::attachObject(
    const void* objectID, void* object, void* cleanupCookie,
    object_cleanup_func func)
{
    AutoMutex _l(mLock);
    LOGV("Attaching object %p to binder %p (manager=%p)", object, this, &mObjects);
    mObjects.attach(objectID, object, cleanupCookie, func);
}

void* BpBinder::findObject(const void* objectID) const
{
    AutoMutex _l(mLock);
    return mObjects.find(objectID);
}

void BpBinder::detachObject(const void* objectID)
{
    AutoMutex _l(mLock);
    mObjects.detach(objectID);
}

BpBinder* BpBinder::remoteBinder()
{
    return this;
}

BpBinder::~BpBinder()
{
    LOGV("Destroying BpBinder %p handle %d\n", this, mHandle);

    IPCThreadState* ipc = IPCThreadState::self();

    mLock.lock();
    Vector<Obituary>* obits = mObituaries;
    if(obits != NULL) {
        if (ipc) ipc->clearDeathNotification(mHandle, this);
        mObituaries = NULL;
    }
    mLock.unlock();

    if (obits != NULL) {
        // XXX Should we tell any remaining DeathRecipient
        // objects that the last strong ref has gone away, so they
        // are no longer linked?
        delete obits;
    }

    if (ipc) {
        ipc->expungeHandle(mHandle, this);
        // 当一个Binder代理对象销毁时，当前线程就会调用内部的IPCThreadState对象函数来减少相应的Binder引用对象的弱引用计数
        ipc->decWeakHandle(mHandle);
    }
}

// 当一个Binder代理对象不再被任何强指针引用时，Cient进程就会请求Binder驱动减少相应的Binder引用对象的强引用计数
void BpBinder::onFirstRef()
{
    LOGV("onFirstRef BpBinder %p handle %d\n", this, mHandle);
    IPCThreadState* ipc = IPCThreadState::self();
    // 调用相应的函数以增加相应的Binder引用对象的强引用计数
    if (ipc) ipc->incStrongHandle(mHandle);
}

// Binder代理对象的引用计数与它所引用的Binder引用对象的引用计数是多对一的关系
// 这样做可以减少Client进程和Binder驱动程序之间的交互
// 减少它们之间的协议来往
void BpBinder::onLastStrongRef(const void* id)
{
    LOGV("onLastStrongRef BpBinder %p handle %d\n", this, mHandle);
    IF_LOGV() {
        printRefs();
    }
    IPCThreadState* ipc = IPCThreadState::self();
    // 调用函数以减少Binder引用对象的强引用计数
    if (ipc) ipc->decStrongHandle(mHandle);
}

bool BpBinder::onIncStrongAttempted(uint32_t flags, const void* id)
{
    LOGV("onIncStrongAttempted BpBinder %p handle %d\n", this, mHandle);
    IPCThreadState* ipc = IPCThreadState::self();
    return ipc ? ipc->attemptIncStrongHandle(mHandle) == NO_ERROR : false;
}

// ---------------------------------------------------------------------------

}; // namespace android
