#ifndef IFREGSERVICE_H_
#define IFREGSERVICE_H_

#include <utils/RefBase.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>

#define FREG_SERVICE "shy.luo.FregService"

using namespace android;

class IFregService: public IInterface
{
public:
	DECLARE_META_INTERFACE(FregService);
	virtual int32_t getVal() = 0;
	virtual void setVal(int32_t val) = 0;
};

class BnFregService: public BnInterface<IFregService>
{
public:
	virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0);
};

#endif
