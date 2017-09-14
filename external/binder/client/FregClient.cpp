#define LOG_TAG "FregClient"

#include <utils/Log.h>
#include <binder/IServiceManager.h>

#include "../common/IFregService.h"

// client模块的入口函数
int main()
{
	// 获取一个类型为BpBinder的代理对象
	sp<IBinder> binder = defaultServiceManager()->getService(String16(FREG_SERVICE));
	if(binder == NULL) {
		LOGE("Failed to get freg service: %s.\n", FREG_SERVICE);
		return -1;
	}

	// 获得IFregService接口
	sp<IFregService> service = IFregService::asInterface(binder);
	if(service == NULL) {
		LOGE("Failed to get freg service interface.\n");
		return -2;
	}

	printf("Read original value from FregService:\n");

	int32_t val = service->getVal();
	printf(" %d.\n", val);

	printf("Add value 1 to FregService.\n");		

	// 调用接口
	val += 1;
	service->setVal(val);

	printf("Read the value from FregService again:\n");
	
	val = service->getVal();
        printf(" %d.\n", val); 

	return 0;
}
