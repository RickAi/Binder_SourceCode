#ifndef IFREGSERVICE_H_
#define IFREGSERVICE_H_

#include <utils/RefBase.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>

// 定义宏FREG_SERVICE来描述Service组件FregService注册到Service Manager的名称
#define FREG_SERVICE "shy.luo.FregService"

using namespace android;

// 定义一个硬件访问服务接口
class IFregService: public IInterface
{
public:
	DECLARE_META_INTERFACE(FregService);
	// 成员函数
	virtual int32_t getVal() = 0;
	virtual void setVal(int32_t val) = 0;
};

// 定义一个Binder本地对象类BnFregService
class BnFregService: public BnInterface<IFregService>
{
public:
	virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0);
};

#endif
