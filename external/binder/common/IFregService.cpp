#define LOG_TAG "IFregService"

#include <utils/Log.h>

#include "IFregService.h"

using namespace android;

enum 
{
	GET_VAL = IBinder::FIRST_CALL_TRANSACTION,
	SET_VAL
};

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
		Parcel data;
		data.writeInterfaceToken(IFregService::getInterfaceDescriptor());
		
		Parcel reply;
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

status_t BnFregService::onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
	switch(code)
	{
		case GET_VAL:
		{
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
