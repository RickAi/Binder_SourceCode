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

#ifndef ANDROID_IPC_THREAD_STATE_H
#define ANDROID_IPC_THREAD_STATE_H

#include <utils/Errors.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <utils/Vector.h>

#ifdef HAVE_WIN32_PROC
typedef  int  uid_t;
#endif

// ---------------------------------------------------------------------------
namespace android {

// 每一个使用了Binder进程间通信机制的进程都有一个Binder线程池，用来处理进程间通信请求
// 对于每一个Binder线程来说，它的内部都有一个IPCThread对象
// 可以通过IPCThreadState类的静态成员函数self来获取，并且调用它的成员函数transact来和
// Binder驱动交互
// 在IPCThreadState类的成员函数transact内部，与Binder驱动的交互又是通过调用talkWithDriver
// 来实现
// 一方面负责向Binder驱动发送进程间通信请求，另一方面又负责接受来自Binder驱动程序的进程间通信请求
class IPCThreadState
{
public:
    static  IPCThreadState*     self();
    
            sp<ProcessState>    process();
            
            status_t            clearLastError();

            int                 getCallingPid();
            int                 getCallingUid();

            void                setStrictModePolicy(int32_t policy);
            int32_t             getStrictModePolicy() const;

            void                setLastTransactionBinderFlags(int32_t flags);
            int32_t             getLastTransactionBinderFlags() const;

            int64_t             clearCallingIdentity();
            void                restoreCallingIdentity(int64_t token);
            
            void                flushCommands();

            void                joinThreadPool(bool isMain = true);
            
            // Stop the local process.
            void                stopProcess(bool immediate = true);
            
            status_t            transact(int32_t handle,
                                         uint32_t code, const Parcel& data,
                                         Parcel* reply, uint32_t flags);

            void                incStrongHandle(int32_t handle);
            void                decStrongHandle(int32_t handle);
            void                incWeakHandle(int32_t handle);
            void                decWeakHandle(int32_t handle);
            status_t            attemptIncStrongHandle(int32_t handle);
    static  void                expungeHandle(int32_t handle, IBinder* binder);
            status_t            requestDeathNotification(   int32_t handle,
                                                            BpBinder* proxy); 
            status_t            clearDeathNotification( int32_t handle,
                                                        BpBinder* proxy); 

    static  void                shutdown();
    
    // Call this to disable switching threads to background scheduling when
    // receiving incoming IPC calls.  This is specifically here for the
    // Android system process, since it expects to have background apps calling
    // in to it but doesn't want to acquire locks in its services while in
    // the background.
    static  void                disableBackgroundScheduling(bool disable);
    
private:
                                IPCThreadState();
                                ~IPCThreadState();

            status_t            sendReply(const Parcel& reply, uint32_t flags);
            status_t            waitForResponse(Parcel *reply,
                                                status_t *acquireResult=NULL);
            status_t            talkWithDriver(bool doReceive=true);
            status_t            writeTransactionData(int32_t cmd,
                                                     uint32_t binderFlags,
                                                     int32_t handle,
                                                     uint32_t code,
                                                     const Parcel& data,
                                                     status_t* statusBuffer);
            status_t            executeCommand(int32_t command);
            
            void                clearCaller();
            
    static  void                threadDestructor(void *st);
    static  void                freeBuffer(Parcel* parcel,
                                           const uint8_t* data, size_t dataSize,
                                           const size_t* objects, size_t objectsSize,
                                           void* cookie);
    // 指向一个ProcessState对象，负责初始化Binder设备
    // 打开设备文件/dev/binder，以及将设备文件/dev/binder映射到进程的地址空间
    // 由于这个ProcessState对象在进程范围内是唯一的
    // 因此，Binder线程池中的每一个线程都可以通过它来和Binder驱动程序建立连接
    const   sp<ProcessState>    mProcess;
    const   pid_t               mMyThreadId;
            Vector<BBinder*>    mPendingStrongDerefs;
            Vector<RefBase::weakref_type*> mPendingWeakDerefs;
            
            Parcel              mIn;
            Parcel              mOut;
            status_t            mLastError;
            pid_t               mCallingPid;
            uid_t               mCallingUid;
            int32_t             mStrictModePolicy;
            int32_t             mLastTransactionBinderFlags;
};

}; // namespace android

// ---------------------------------------------------------------------------

#endif // ANDROID_IPC_THREAD_STATE_H
