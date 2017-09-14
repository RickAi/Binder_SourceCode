#define LOG_TAG "IFregService"

#include <utils/Log.h>

#include "IFregService.h"

using namespace android;

enum 
{
	// 定义了两个进程间通信代码
	GET_VAL = IBinder::FIRST_CALL_TRANSACTION,
	SET_VAL
};

// 定义代理对象类
// 继承BnInterface
// 实现IFregService接口
class BpFregService: public BpInterface<IFregService>
{
public:
	BpFregService(const sp<IBinder>& impl) 
		: BpInterface<IFregService>(impl)
	{

	}

public:
	int32_t getVal()
	{
		// 将要传递的数据封装到data中
		Parcel data;
		data.writeInterfaceToken(IFregService::getInterfaceDescriptor());
		
		Parcel reply;
		// 获取一个代理对象，调用transact函数请求运行在Server进程的一个Binder本地对象
		// 执行GET_VAL操作
		// 返回的结果是一个整数，封装在reply中
		remote()->transact(GET_VAL, data, &reply);

		int32_t val = reply.readInt32();
	
		return val;
	}

	void setVal(int32_t val)
        {
                Parcel data;
                data.writeInterfaceToken(IFregService::getInterfaceDescriptor());
		data.writeInt32(val);

                Parcel reply;
                remote()->transact(SET_VAL, data, &reply);
        }

};

IMPLEMENT_META_INTERFACE(FregService, "shy.luo.IFregService");

// 定义了BnFregService成员函数onTransact
// 将GET_VAL和SET_VAL进程间通信请求分发给其子类的成员函数getVal和setVal来处理
status_t BnFregService::onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
	switch(code)
	{
		case GET_VAL:
		{
			// 在进行进程间通信请求分发给其子类处理之前，会首先调用宏CHECK_INTERFACE来检查该进程
			// 间通信请求的合法性
			// 即检查该请求是否是由FregService组件的代理对象发送过来的
			CHECK_INTERFACE(IFregService, data, reply);
			
			int32_t val = getVal();
			reply->writeInt32(val);
			
			return NO_ERROR;
		}
		case SET_VAL:
                {
                        CHECK_INTERFACE(IFregService, data, reply);
			
			int32_t val = data.readInt32();
			setVal(val);

                        return NO_ERROR;
                }
		default:
		{
			return BBinder::onTransact(code, data, reply, flags);
		}
	}
}
