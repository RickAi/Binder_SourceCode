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

//
#ifndef ANDROID_IINTERFACE_H
#define ANDROID_IINTERFACE_H

#include <binder/Binder.h>

namespace android {

// ----------------------------------------------------------------------

class IInterface : public virtual RefBase
{
public:
            IInterface();
            sp<IBinder>         asBinder();
            sp<const IBinder>   asBinder() const;
            
protected:
    virtual                     ~IInterface();
    virtual IBinder*            onAsBinder() = 0;
};

// ----------------------------------------------------------------------

// 句柄值为0的Binder代理对象封装为一个Service Manager代理对象
template<typename INTERFACE>
inline sp<INTERFACE> interface_cast(const sp<IBinder>& obj)
{
    return INTERFACE::asInterface(obj);
}

// ----------------------------------------------------------------------

// Binder本地对象，对应着Binder驱动中的Binder实体对象
// INTERFACE: 模板参数，是一个由进程自定义的Service组件接口
// BBinder: Binder本地类
template<typename INTERFACE>
class BnInterface : public INTERFACE, public BBinder
{
public:
    virtual sp<IInterface>      queryLocalInterface(const String16& _descriptor);
    virtual const String16&     getInterfaceDescriptor() const;

protected:
    virtual IBinder*            onAsBinder();
};

// ----------------------------------------------------------------------

// Binder代理对象，对应这Binder驱动中的Binder引用对象
// BpRefBase: Binder代理类
template<typename INTERFACE>
class BpInterface : public INTERFACE, public BpRefBase
{
public:
                                BpInterface(const sp<IBinder>& remote);

protected:
    virtual IBinder*            onAsBinder();
};

// ----------------------------------------------------------------------

// 定义一个静态成员变量descriptor，通过getInterfaceDescriptor来过去
// 定义一个asInterface，用来将一个IBinder对象转换为IFregService接口
#define DECLARE_META_INTERFACE(INTERFACE)                               \
    static const android::String16 descriptor;                          \
    static android::sp<I##INTERFACE> asInterface(                       \
            const android::sp<android::IBinder>& obj);                  \
    virtual const android::String16& getInterfaceDescriptor() const;    \
    I##INTERFACE();                                                     \
    virtual ~I##INTERFACE();                                            \

// 将descriptor设置为shy.luo.IFregService
// 实现了IFregService的析造函数，析构函数
// asInterface用来将一个IBinder对象转换为一个IFregService接口
#define IMPLEMENT_META_INTERFACE(INTERFACE, NAME)                       \
    const android::String16 I##INTERFACE::descriptor(NAME);             \
    const android::String16&                                            \
            I##INTERFACE::getInterfaceDescriptor() const {              \
        return I##INTERFACE::descriptor;                                \
    }                                                                   \
    // 参数obj指向一个类型为BnFregService的Binder本地对象
    // 或者一个类型为BpBinder的Binder代理对象
    // 否则就返回NULL
    android::sp<I##INTERFACE> I##INTERFACE::asInterface(                \
            const android::sp<android::IBinder>& obj)                   \
    {                                                                   \
        android::sp<I##INTERFACE> intr;                                 \
        if (obj != NULL) {                                              \
            // 如果参数是一个BnFregService对象，那么就会调用queryLocalInterface返回一个IFregService接口
            // 如果obj指向的是一个BpBinder代理对象，那么会返回NULL,接着封装成一个BpFregService对象
            intr = static_cast<I##INTERFACE*>(                          \
                obj->queryLocalInterface(                               \
                        I##INTERFACE::descriptor).get());               \
            if (intr == NULL) {                                         \
                intr = new Bp##INTERFACE(obj);                          \
            }                                                           \
        }                                                               \
        return intr;                                                    \
    }                                                                   \
    I##INTERFACE::I##INTERFACE() { }                                    \
    I##INTERFACE::~I##INTERFACE() { }                                   \


#define CHECK_INTERFACE(interface, data, reply)                         \
    if (!data.checkInterface(this)) { return PERMISSION_DENIED; }       \


// ----------------------------------------------------------------------
// No user-serviceable parts after this...

template<typename INTERFACE>
inline sp<IInterface> BnInterface<INTERFACE>::queryLocalInterface(
        const String16& _descriptor)
{
    if (_descriptor == INTERFACE::descriptor) return this;
    return NULL;
}

template<typename INTERFACE>
inline const String16& BnInterface<INTERFACE>::getInterfaceDescriptor() const
{
    return INTERFACE::getInterfaceDescriptor();
}

template<typename INTERFACE>
IBinder* BnInterface<INTERFACE>::onAsBinder()
{
    return this;
}

template<typename INTERFACE>
inline BpInterface<INTERFACE>::BpInterface(const sp<IBinder>& remote)
    : BpRefBase(remote)
{
}

template<typename INTERFACE>
inline IBinder* BpInterface<INTERFACE>::onAsBinder()
{
    return remote();
}
    
// ----------------------------------------------------------------------

}; // namespace android

#endif // ANDROID_IINTERFACE_H
