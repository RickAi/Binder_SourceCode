/* binder.c
 *
 * Android IPC Subsystem
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <asm/cacheflush.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include "binder.h"

static DEFINE_MUTEX(binder_lock);
static HLIST_HEAD(binder_procs);
static struct binder_node *binder_context_mgr_node;
static uid_t binder_context_mgr_uid = -1;
static int binder_last_id;
static struct proc_dir_entry *binder_proc_dir_entry_root;
static struct proc_dir_entry *binder_proc_dir_entry_proc;
static struct hlist_head binder_dead_nodes;
static HLIST_HEAD(binder_deferred_list);
static DEFINE_MUTEX(binder_deferred_lock);

static int binder_read_proc_proc(
	char *page, char **start, off_t off, int count, int *eof, void *data);

/* This is only defined in include/asm-arm/sizes.h */
#ifndef SZ_1K
#define SZ_1K                               0x400
#endif

#ifndef SZ_4M
#define SZ_4M                               0x400000
#endif

#define FORBIDDEN_MMAP_FLAGS                (VM_WRITE)

#define BINDER_SMALL_BUF_SIZE (PAGE_SIZE * 64)

enum {
	BINDER_DEBUG_USER_ERROR             = 1U << 0,
	BINDER_DEBUG_FAILED_TRANSACTION     = 1U << 1,
	BINDER_DEBUG_DEAD_TRANSACTION       = 1U << 2,
	BINDER_DEBUG_OPEN_CLOSE             = 1U << 3,
	BINDER_DEBUG_DEAD_BINDER            = 1U << 4,
	BINDER_DEBUG_DEATH_NOTIFICATION     = 1U << 5,
	BINDER_DEBUG_READ_WRITE             = 1U << 6,
	BINDER_DEBUG_USER_REFS              = 1U << 7,
	BINDER_DEBUG_THREADS                = 1U << 8,
	BINDER_DEBUG_TRANSACTION            = 1U << 9,
	BINDER_DEBUG_TRANSACTION_COMPLETE   = 1U << 10,
	BINDER_DEBUG_FREE_BUFFER            = 1U << 11,
	BINDER_DEBUG_INTERNAL_REFS          = 1U << 12,
	BINDER_DEBUG_BUFFER_ALLOC           = 1U << 13,
	BINDER_DEBUG_PRIORITY_CAP           = 1U << 14,
	BINDER_DEBUG_BUFFER_ALLOC_ASYNC     = 1U << 15,
};
static uint32_t binder_debug_mask = BINDER_DEBUG_USER_ERROR |
	BINDER_DEBUG_FAILED_TRANSACTION | BINDER_DEBUG_DEAD_TRANSACTION;
module_param_named(debug_mask, binder_debug_mask, uint, S_IWUSR | S_IRUGO);
static int binder_debug_no_lock;
module_param_named(proc_no_lock, binder_debug_no_lock, bool, S_IWUSR | S_IRUGO);
static DECLARE_WAIT_QUEUE_HEAD(binder_user_error_wait);
static int binder_stop_on_user_error;
static int binder_set_stop_on_user_error(
	const char *val, struct kernel_param *kp)
{
	int ret;
	ret = param_set_int(val, kp);
	if (binder_stop_on_user_error < 2)
		wake_up(&binder_user_error_wait);
	return ret;
}
module_param_call(stop_on_user_error, binder_set_stop_on_user_error,
	param_get_int, &binder_stop_on_user_error, S_IWUSR | S_IRUGO);

#define binder_user_error(x...) \
	do { \
		if (binder_debug_mask & BINDER_DEBUG_USER_ERROR) \
			printk(KERN_INFO x); \
		if (binder_stop_on_user_error) \
			binder_stop_on_user_error = 2; \
	} while (0)

enum {
	BINDER_STAT_PROC,
	BINDER_STAT_THREAD,
	BINDER_STAT_NODE,
	BINDER_STAT_REF,
	BINDER_STAT_DEATH,
	BINDER_STAT_TRANSACTION,
	BINDER_STAT_TRANSACTION_COMPLETE,
	BINDER_STAT_COUNT
};

struct binder_stats {
	int br[_IOC_NR(BR_FAILED_REPLY) + 1];
	int bc[_IOC_NR(BC_DEAD_BINDER_DONE) + 1];
	int obj_created[BINDER_STAT_COUNT];
	int obj_deleted[BINDER_STAT_COUNT];
};

static struct binder_stats binder_stats;

struct binder_transaction_log_entry {
	int debug_id;
	int call_type;
	int from_proc;
	int from_thread;
	int target_handle;
	int to_proc;
	int to_thread;
	int to_node;
	int data_size;
	int offsets_size;
};
struct binder_transaction_log {
	int next;
	int full;
	struct binder_transaction_log_entry entry[32];
};
struct binder_transaction_log binder_transaction_log;
struct binder_transaction_log binder_transaction_log_failed;

static struct binder_transaction_log_entry *binder_transaction_log_add(
	struct binder_transaction_log *log)
{
	struct binder_transaction_log_entry *e;
	e = &log->entry[log->next];
	memset(e, 0, sizeof(*e));
	log->next++;
	if (log->next == ARRAY_SIZE(log->entry)) {
		log->next = 0;
		log->full = 1;
	}
	return e;
}

// 用来描述待处理的工作项，这些工作项可能属于一个进程或者线程。
struct binder_work {
	// entry: 	用来将该结构体嵌入到一个宿主结构中
	struct list_head entry;
	enum {
		BINDER_WORK_TRANSACTION = 1,
		BINDER_WORK_TRANSACTION_COMPLETE,
		BINDER_WORK_NODE,
		BINDER_WORK_DEAD_BINDER,
		BINDER_WORK_DEAD_BINDER_AND_CLEAR,
		BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
	// type:	用来描述工作项的类型
	// 根据type值, 可以判断出binder_work结构体嵌入到了什么类型的宿主结构
	} type;
};

// 用来描述一个Binder实体对象
// 每一个Service组件在Binder驱动程序中都对应着一个Binder实体对象, 用来描述它在内核中的状态
// Binder驱动程序通过强引用计数和弱引用计数来维护它们的生命周期
struct binder_node {
	// debug_id: 来用标志一个Binder实体对象的身体，用来调试用的
	int debug_id;
	// 当一个Binder实体对象的引用计数0->1或者1->0时，Binder驱动程序会请求相应的Service增加或
	// 减少其引用计数; 这时，Binder驱动会将该引用计数修改操作封装成binder_node的工作项，work变量
	// 的值将被设为BINDER_WORK_NODE并添加到相应的todo队列中等待处理
	struct binder_work work;
	union {
		// rb_node:		红黑树中的一个节点
		struct rb_node rb_node;
		// dead_node:	如果宿主进程已经死亡，dead_node将被保存在一个全局hash列表中
		struct hlist_node dead_node;
	};
	// proc:		指向一个Binder实体对象的宿主进程
	// [这些宿主进程通过一个binder_proc结构体来描述，宿主进程使用一个红黑树来维护它内部所有的Binder实体对象]
	struct binder_proc *proc;
	// refs:		binder_ref hash列表，通过这个变量可以知道哪些Client组件引用了同一个Binder实体对象
	struct hlist_head refs;
	// internal_strong_refs/local_strong_refs: Binder实体对象强引用计数
	int internal_strong_refs;
	// local_weak_refs: 弱引用计数
	int local_weak_refs;
	int local_strong_refs;
	// ptr：			指向用户空间中的Service组件内部的引用计数对象的地址
	void __user *ptr;
	// cookie: 		指向用户空间中的Service组件地址
	void __user *cookie;
	unsigned has_strong_ref : 1;
	// pending_strong_ref/pending_weak_ref: 正在增加或减少引用计数会被设置为1
	unsigned pending_strong_ref : 1;
	// has_strong_ref/has_weak_ref: 当Binder实体对象请求Service组件执行操作时会被设置为1
	unsigned has_weak_ref : 1;
	unsigned pending_weak_ref : 1;
	// has_async_transaction: 是否在执行异步事务
	// [Binder驱动程序会将事务保存在一个线程的todo队列中，表示要由该线程来处理的事务，每一个事务都关联着一个
	// Binder实体对象，表示该事务的目标处理对象，即要求与该Binder实体对象对应的Service组件在指定的线程中处理该事务，
	// 当Binder驱动发现一个事务是异步的，就会将它保存在目标Bindr实体对象的一个异步事务队列中]
	unsigned has_async_transaction : 1;
	// accept_fds：	用来描述一个Binder实体对象是否可以接受包含有文件描述符的进程间通信数据
	// [如果允许，当一个进程向另一个进程发送数据中含有文件描述符时，Binder驱动会自动在目标进程中打开一个相同文件]
	unsigned accept_fds : 1;
	// min_priority： Binder实体对象在处理一个来自Client进程的请求时，它的对应Server进程中的进程应该具备的最小线程优先级
	// 这样能保证该Binder实体对象对应的Service组件在一个有一定优先级的线程中处理来自Client进程的请求
	int min_priority : 8;
	// async_todo:	异步事务队列; 即单向的进程间通信请求，不需要等待应答
	// [异步事务的优先级低于同步事务，同一时刻，一个Binder实体对象的所有异步事务至多只有一个会得到处理
	// 同步事务没有这个限制]
	struct list_head async_todo;
};

// 用来描述一个Service组件的死亡接收通知
// 正常情况下，Service组件被其他Client进程引用时是不可被销毁的
// 如果Service组件意外崩溃死亡，Client进程将会收到Service组件死亡的通知
// [当驱动要向Client发送死亡通知时，会将一个binder_ref_death结构体封装
// 成一个工作项，根据实际情况来设置work变量的值，最后发送到Client的todo队列中]
//
// 死亡通知的２种情况：BINDER_WORK_DEAD_BINDER
// 1. 驱动程序检测到了Service组件死亡：binder_node->refs [-] binder_ref_death
// 2. Client注册死亡通知时，如果Service已经死亡
//
//　注销死亡通知时也会向Client进程todo队列发送一个类型为binder_ref_death的工作项
// １．注销时Service没有死亡，驱动会找到之前注册的binder_ref_death结构体，将work修改为
// BINDER_WORK_CLEAR_DEATH_NOTIFICATION, 然后再封装成工作项添加到Client的todo队列
// 2. 注销时Service已经死亡，驱动会找到binder_ref_death结构体，将work修改为
// BINDER_WORK_DEAD_BINDER_AND_CLEAR. 然后再封装成工作项添加到Client的todo队列
struct binder_ref_death {
	// 用来标志一个具体的死亡通知类型; 通过它也能够区分注销的结果
	struct binder_work work;
	// 用来保存负责接收死亡通知的对象的地址
	void __user *cookie;
};

// 同一个Binder实体对象可能会同时被多个Client组件引用
// 使用binder_ref来描述这些引用关系
// 将引用了同一个Binder实体对象的所有引用都保存在一个hash列表中
//
// 用来描述一个Binder引用对象
// 每个Client组件在Binder驱动中度对应有一个Binder引用对象
// 用来描述它在内核的状态
// 驱动通过强引用计数与弱引用计数来维护它们在生命周期
struct binder_ref {
	/* Lookups needed: */
	/*   node + proc => ref (transaction) */
	/*   desc + proc => ref (transaction, inc/dec ref) */
	/*   node => refs + procs (proc exit) */
	// 用来标志Binder应用对象的身份，帮助调试用
	int debug_id;
	// 一个宿主进程使用两个红黑树来保存它内部所有的引用对象
	// 分别以句柄值和对应的Binder实体对象的地址作为关键字来保存Binder引用对象
	// rb_node_desc, rb_node_node 为这两个红黑树的节点
	struct rb_node rb_node_desc;
	struct rb_node rb_node_node;
	// Binder实体对象hash列表的节点
	struct hlist_node node_entry;
	// 引用对象的宿主进程
	struct binder_proc *proc;
	// 描述一个Binder引用对象所引用的Binder实体对象
	struct binder_node *node;
	// 句柄值描述符，用来描述一个Binder引用对象
	// 句柄值在进程范围内唯一，不同进程见同一句柄值可能代表这不同Service组件
	//
	// 在Client进程的用户空间中，访问Service组件通过以下顺序
	// Client->句柄值->binder_ref->binder_node->Service
	uint32_t desc;
	// 强弱引用计数，用来维护引用对象的生命周期
	int strong;
	int weak;
	// 指向死亡接收通知
	// 当Client进程向驱动注册死亡通知时，会创建一个binder_ref_death结构体并保存在death变量中
	struct binder_ref_death *death;
};

// 用来描述一个内核缓冲区，用来在进程间传输数据
// 每一个使用Binder进程间通信的进程在Binder驱动程序中都有一个内核缓冲区列表, 用来保存Binder驱动程序
// 为它分配的内核缓冲区
// 进程使用了两个红黑树来分别保存那些正在使用的内核缓冲区以及空闲的缓冲区
struct binder_buffer {
	// 内核缓冲区列表的一个节点
	struct list_head entry; /* free and allocated entries by addesss */
	// 内核缓冲区红黑树中的一个节点
	struct rb_node rb_node; /* free entry by size or allocated entry */
				/* by address */
	// 如果这个内核缓冲区是空闲的，free变量设置为1
	unsigned free : 1;
	// Service组件的事务处理完后，如果该变量为1, 那么Service组件会请求Binder驱动释放该缓冲区
	unsigned allow_user_free : 1;
	// 如果一个内核缓冲区关联的是异步事务，那么此变量值设置为1
	// Binder驱动限制了分配给异步事务内核缓冲区的大小，这样做可以保证同步事务可以优先得到内核缓冲区，
	// 以便可以快速的对该同步事务进行处理
	unsigned async_transaction : 1;
	// 帮助调试Binder驱动，用来标志内核缓冲区的身份
	unsigned debug_id : 29;
	// 描述这个内核缓冲区正在给那个事务使用
	struct binder_transaction *transaction;

	// 描述这个内核缓冲区正在给那个实体对象使用
	struct binder_node *target_node;
	// 数据缓冲区的大小
	size_t data_size;
	// 偏移数组的大小
	size_t offsets_size;
	// 一块大小可变的数据缓冲区，真正用来保存通信数据的
	// [保存的数据划分为两种类型，一种是普通数据，一种是Binder对象
	// Binder驱动不关心数据缓冲区的普通数据，但是必须知道里面的Binder对象，因为需要根据它们来维护内核
	// 中的Binder实体对象和Binder引用对象的生命周期]
	// [如果数据缓冲区中包含了一个Binder引用，并且该数据缓冲区是传递给另外一个进程的，那么Binder驱动就需要
	// 为另外一个进程创建一个Binder引用对象，并且增加对应的Binder实体对象的引用计数，因为它也被另外的
	// 这个进程引用了。由于数据缓冲区中的普通数据和Binder对象是混合在一起保存的，它们之间没有固定顺序,
	// 因此，Binder驱动就需要额外的数据来寻找里面的Binder对象]
	// 数据缓冲区后面有偏移数组，记录了数据缓冲区中每一个Binder对象在数据缓冲区中的位置
	uint8_t data[0];
};

// binder_proc->deferred_work_node类型
enum {
	// 驱动为进程分配内核缓冲区时，会为内核缓冲区创建一个文件描述符
	// 进程可以通过这个文件描述符将内核缓冲区映射到自己的地址空间
	// 当进程不再需要使用Binder进程间通信机制时，它会通知Binder驱动程序关闭该文件描述符
	// 并且释放之前所分配的内核缓冲区
	// 这不是一个马上就需要完成的操作，所以创建这个类型的工作项来延迟操作
	BINDER_DEFERRED_PUT_FILES    = 0x01,
	// Binder线程睡眠在一个等待队列中，进程可以通过调用函数flush来唤醒这些线程
	// 这时可以创建这个工作项来延迟唤醒空闲的Binder线程操作
	BINDER_DEFERRED_FLUSH        = 0x02,
	// 当进程不再使用Binder通信时，它就会调用函数close来关闭/dev/binder设备，这时候Binder
	// 驱动程序就会释放之前为它分配的资源。
	// 例如，释放结构体bindr_proc，实体对象binder_node，对象引用binder_ref
	// 由于资源释放比较耗时，所以使用这个类型来标记与延迟它们
	BINDER_DEFERRED_RELEASE      = 0x04,
};

// 描述一个正在使用Binder的进程
// 当一个进程调用函数open来打开设备文件/dev/binder时，Binder驱动程序就会为它创建一个binder_proc结构体
// 并且保存在一个全局的hash列表中
// [打开了设备文件/dev/binder之后，需要调用函数mmap将它映射到进程的地址空间
// 实际上是请求Binder驱动程序为它分配一块内核缓冲区,以便可以用来在进程间传输数据]
struct binder_proc {
	// 全局hash列表中的一个节点
	struct hlist_node proc_node;
	// 是一个红黑树的根节点
	// 它以线程ID作为关键字来组织一个进程的Binder线程池
	// 进程可以调用函数ioctl将一个线程注册到Binder驱动程序中，同时，当进程没有足够的空闲
	// 线程在处理进程间通信请求时，Binder驱动程序也可以主动要求进程注册更多的线程到Binder线程池中
	struct rb_root threads;
	// 一个进程内部包含了一系列的Binder实体对象和Binder引用对象
	// 进程使用三个红黑树来组织它们
	// nodes变量描述的是用来组织Binder实体对象，以ptr作为关键字
	struct rb_root nodes;
	// refs_by_desc是用来组织Binder引用对象的，以desc作为关键字
	struct rb_root refs_by_desc;
	// refs_by_desc是用来组织Binder引用对象的，以node作为关键字
	struct rb_root refs_by_node;
	// 进程组ID
	int pid;
	// 用户空间地址是在应用程序进程内部使用的，保存在vma
	struct vm_area_struct *vma;
	// 任务控制块
	struct task_struct *tsk;
	// 打开文件结构体数组
	struct files_struct *files;
	// 一个hash列表，用来保存进程可以延迟执行的工作项
	// 3中类型：
	// enum {
	// BINDER_DEFERRED_PUT_FILES    = 0x01,
	// BINDER_DEFERRED_FLUSH        = 0x02,
	// BINDER_DEFERRED_RELEASE      = 0x04,
	// };
	struct hlist_node deferred_work_node;
	int deferred_work;
	// 内核缓冲区有两个地址
	// 其中一个是内核空间地址，另一个是用户空间地址
	// 内核空间地址在Binder驱动内部使用，保存在buffer
	// [这两个地址指的都是虚拟地址]
	// buffer指向的是一块大的内核缓冲区，Binder驱动程序为了方便对它进行管理，会将它划分成
	// 若干个小块；这些小块的内核缓冲区就是使用binder_buffer来描述的
	// 它们保存在一个列表中，按照地址值从小到大的顺序来排列
	void *buffer;
	// vma和buffer这两个地址相差一个固定的值，保存在user_buffer_offset
	ptrdiff_t user_buffer_offset;

	// 指向的是内核缓冲区列表的头部
	struct list_head buffers;
	// 保存在空闲的红黑树中
	struct rb_root free_buffers;
	// 列表中的小块内核缓冲区有的是正在使用的，即已经分配了物理页面
	// 有的是空闲的，即还没有分配物理页面，分别组织在两个红黑树中
	// 保存在已经分配的红黑树中
	struct rb_root allocated_buffers;
	// 保存了当前可以用来保存异步事务数据的内核缓冲区的大小
	size_t free_async_space;

	// 两个内核缓冲区对应的物理页面保存在这个变量中
	// [page类型是一个数组，每一个元素都指向一个物理页面
	// Binder驱动一开始时只为该内核缓冲区分配一个物理页面，后面不够使用时再分配]
	struct page **pages;
	// 保存Binder驱动程序为进程分配的内核缓冲区的大小
	size_t buffer_size;
	// 保存了空闲内核缓冲区的大小
	uint32_t buffer_free;
	// 当进程接收到一个进程间通信请求时，Binder驱动会将请求封装成一个工作项
	// 然后加入到待处理的工作项队列todo中
	struct list_head todo;
	// 空闲的Binder线程会睡眠在由成员变量wait所描述的一个等待队列中，当它们的宿主进程的待处理工作
	// 项队列增加了新得工作项之后，Binder驱动程序会唤醒这些线程，以便它们可以去处理新的工作项
	wait_queue_head_t wait;
	// 用来统计进程数据的，例如，进程接受到的进程间通信的请求次数
	struct binder_stats stats;
	struct list_head delivered_death;
	// Binder驱动最多可以主动请求进程注册的线程的数量保存在这个变量中
	int max_threads;
	// max_threads不是指线程池中的最大线程数目
	// 每一次主动请求进程注册一个线程时，都会将这个变量加1
	// 而当进程响应这个请求之后，驱动会把这个变量减1
	int requested_threads;
	// 将这个变量加1表示Bindre驱动程序已经主动请求进程注册了多少个线程到Binder线程池中
	int requested_threads_started;
	// 表示进程当前的空闲Binder线程数目
	int ready_threads;
	// 初始化为进程的优先级
	// 这时由于线程是代表其宿主进程来处理一个工作项的
	long default_priority;
};

// 线程的状态
enum {
	// 一个线程注册到Binder程序后，就会通过BC_REGISTER_LOOPER或者BC_ENTER_LOOPER协议来通知驱动
	// 它可以处理进程间通信的请求了
	// 这时Binder驱动程序就会将它的状态设置为以下两个状态
	// 如果一个线程时应用程序主动注册的，那么它就会通过BC_ENTER_LOOPER协议来通知Binder驱动
	// 如果一个线程是Binder驱动请求创建的，那么就会通过BC_REGISTER_LOOPER协议来通知Binder驱动
	BINDER_LOOPER_STATE_REGISTERED  = 0x01,
	BINDER_LOOPER_STATE_ENTERED     = 0x02,
	// 当Binder线程退出时，会通过设置成以下状态
	BINDER_LOOPER_STATE_EXITED      = 0x04,
	// 当出现异常时会设置成以下状态
	BINDER_LOOPER_STATE_INVALID     = 0x08,
	// 当Bindre线程处于空闲状态时，驱动会把它的状态设置为以下
	BINDER_LOOPER_STATE_WAITING     = 0x10,
	// 一个线程注册到Binder驱动程序时，Binder驱动程序就会为它创建一个binder_thread结构体，
	// 并且将它的状态初始化为BINDER_LOOPER_STATE_NEED_RETURN
	// 表示该线程需要马上返回到用户空间
	// 由于一个线程在注册为Binder线程时可能还没有准备好去处理进程间通信的请求
	// 因此，最好返回到用户空间去做准备工作
	// 此外，当进程调用函数flush刷新Binder线程池时,Binder线程池中的线程状态也会被重置为BINDER_LOOPER_STATE_NEED_RETURN
	BINDER_LOOPER_STATE_NEED_RETURN = 0x20
};

// 用来描述Binder线程池中的一个线程
struct binder_thread {
	// 指向宿主进程，binder_proc使用一个红黑树来组织其Binder线程池中的线程
	struct binder_proc *proc;
	// binder_proc红黑树的节点
	struct rb_node rb_node;
	// 线程id
	int pid;
	// 线程状态
	int looper;
	// 当驱动准备将事务交给一个Binder线程处理时，它就会把该事务封装成一个binder_transaction结构体
	// 把它添加到事务堆栈中
	struct binder_transaction *transaction_stack;
	// 当一个来自client进程的请求指定要由某个Binder线程处理时，这个请求就会加入到相应的todo队列中
	// 并且唤醒这个线程
	struct list_head todo;
	// 一个Binder线程如果出现了异常情况，那么驱动会将相应的错误码保存在return_error和return_error2中
	uint32_t return_error; /* Write failed, return error code in read buf */
	uint32_t return_error2; /* Write failed, return error code in read */
		/* buffer. Used when sending a reply to a dead process that */
		/* we are also waiting on */
	// 当一个Binder线程在处理一个事务T1并需要依赖于其他的Binder来处理另外一个事务T2时，
	// 它就会睡眠在由成员变量wait所描述的一个等待队列中，直到T2处理完成
	wait_queue_head_t wait;
	// 用来统计Binder线程数据
	struct binder_stats stats;
};

// 用来描述一个事务，每个事务都关联着一个目标Binder实体对象
// 事务数据->缓冲区->实体对象->Service组件
// 
// 用来描述进程间通信过程，又称事务
struct binder_transaction {
	// 用来标志一个事务结构体身份，调试Binder驱动用的
	int debug_id;
	// 当Binder驱动为目标进程或者目标线程创建了一个事务时，就会将该事务的成员变量work值
	// 设置为BINDER_WORK_TRANSACTION
	// 将它添加到目标进程或者目标线程的todo队列中去等待处理
	struct binder_work work;
	// 发起事务的线程，又称源线程
	struct binder_thread *from;
	// 一个事务所依赖的另外一个事务
	struct binder_transaction *from_parent;
	// 负责处理该事务的进程和线程，又称目标进程、目标线程
	struct binder_proc *to_proc;
	struct binder_thread *to_thread;
	// 下一个需要处理的事务
	// [一个场景：
	// A<T1> -> C<T3> -> A ]
	struct binder_transaction *to_parent;
	// 区分是同步还是异步
	unsigned need_reply : 1;
	/*unsigned is_dead : 1;*/ /* not used at the moment */
	// 驱动为事务分配的一块内核缓冲区
	// 里面保存着进程间的通信数据
	struct binder_buffer *buffer;
	// 从进程间通信数据中拷贝过来的
	unsigned int	code;
	unsigned int	flags;
	// 源线程的优先级
	long	priority;
	// 一个线程在处理一个事务时，Binder驱动需要修改它的线程优先级，以便满足院系那成和目标Service组件的要求
	// Binder驱动在修改一个线程的优先级之前，会将它的线程优先级保存在一个事务结构体的成员变量saved_priority中
	// 以便线程处理完成该事务后可以恢复原来的优先级
	long	saved_priority;
	// 源线程的id
	uid_t	sender_euid;
};

static void binder_defer_work(struct binder_proc *proc, int defer);

/*
 * copied from get_unused_fd_flags
 */
int task_get_unused_fd_flags(struct binder_proc *proc, int flags)
{
	struct files_struct *files = proc->files;
	int fd, error;
	struct fdtable *fdt;
	unsigned long rlim_cur;
	unsigned long irqs;

	if (files == NULL)
		return -ESRCH;

	error = -EMFILE;
	spin_lock(&files->file_lock);

repeat:
	fdt = files_fdtable(files);
	fd = find_next_zero_bit(fdt->open_fds->fds_bits, fdt->max_fds,
				files->next_fd);

	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
	rlim_cur = 0;
	if (lock_task_sighand(proc->tsk, &irqs)) {
		rlim_cur = proc->tsk->signal->rlim[RLIMIT_NOFILE].rlim_cur;
		unlock_task_sighand(proc->tsk, &irqs);
	}
	if (fd >= rlim_cur)
		goto out;

	/* Do we need to expand the fd array or fd set?  */
	error = expand_files(files, fd);
	if (error < 0)
		goto out;

	if (error) {
		/*
		 * If we needed to expand the fs array we
		 * might have blocked - try again.
		 */
		error = -EMFILE;
		goto repeat;
	}

	FD_SET(fd, fdt->open_fds);
	if (flags & O_CLOEXEC)
		FD_SET(fd, fdt->close_on_exec);
	else
		FD_CLR(fd, fdt->close_on_exec);
	files->next_fd = fd + 1;
#if 1
	/* Sanity check */
	if (fdt->fd[fd] != NULL) {
		printk(KERN_WARNING "get_unused_fd: slot %d not NULL!\n", fd);
		fdt->fd[fd] = NULL;
	}
#endif
	error = fd;

out:
	spin_unlock(&files->file_lock);
	return error;
}

/*
 * copied from fd_install
 */
static void task_fd_install(
	struct binder_proc *proc, unsigned int fd, struct file *file)
{
	struct files_struct *files = proc->files;
	struct fdtable *fdt;

	if (files == NULL)
		return;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	BUG_ON(fdt->fd[fd] != NULL);
	rcu_assign_pointer(fdt->fd[fd], file);
	spin_unlock(&files->file_lock);
}

/*
 * copied from __put_unused_fd in open.c
 */
static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	__FD_CLR(fd, fdt->open_fds);
	if (fd < files->next_fd)
		files->next_fd = fd;
}

/*
 * copied from sys_close
 */
static long task_close_fd(struct binder_proc *proc, unsigned int fd)
{
	struct file *filp;
	struct files_struct *files = proc->files;
	struct fdtable *fdt;
	int retval;

	if (files == NULL)
		return -ESRCH;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd >= fdt->max_fds)
		goto out_unlock;
	filp = fdt->fd[fd];
	if (!filp)
		goto out_unlock;
	rcu_assign_pointer(fdt->fd[fd], NULL);
	FD_CLR(fd, fdt->close_on_exec);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);
	retval = filp_close(filp, files);

	/* can't restart close syscall because file table entry was cleared */
	if (unlikely(retval == -ERESTARTSYS ||
		     retval == -ERESTARTNOINTR ||
		     retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK))
		retval = -EINTR;

	return retval;

out_unlock:
	spin_unlock(&files->file_lock);
	return -EBADF;
}

static void binder_set_nice(long nice)
{
	long min_nice;
	if (can_nice(current, nice)) {
		set_user_nice(current, nice);
		return;
	}
	min_nice = 20 - current->signal->rlim[RLIMIT_NICE].rlim_cur;
	if (binder_debug_mask & BINDER_DEBUG_PRIORITY_CAP)
		printk(KERN_INFO "binder: %d: nice value %ld not allowed use "
		       "%ld instead\n", current->pid, nice, min_nice);
	set_user_nice(current, min_nice);
	if (min_nice < 20)
		return;
	binder_user_error("binder: %d RLIMIT_NICE not set\n", current->pid);
}

// 计算一个内核缓冲区binder_buffer的大小时，需要考虑它在进程内核缓冲区列表buffers中的位置
static size_t binder_buffer_size(
	struct binder_proc *proc, struct binder_buffer *buffer)
{
	if (list_is_last(&buffer->entry, &proc->buffers))
		// 如果是列表中的最后一个元素
		// 那么描述的内核缓冲区的有效数据块成员变量data开始
		// 一直到Binder驱动程序为进程所分配的一块连续内核地址空间的末尾
		// 因此，计算Binder驱动为进程proc分配的内核地址空间的末尾地址
		// 然后再减去内核缓冲区buffer的成员变量data的地址
		// 最后得到内核缓冲区buffer的有效数据块的大小
		return proc->buffer + proc->buffer_size - (void *)buffer->data;
	else
		// 如果不是最后一个元素
		// 那么大小等于下一个内核缓冲区的起始地址，再减去它的成员变量data的地址
		return (size_t)list_entry(buffer->entry.next,
			struct binder_buffer, entry) - (size_t)buffer->data;
}

// 将一个空间的内核缓冲区加入到进程的空闲内核缓冲区红黑树中
// new_buffer; 将被加入到目标进程proc的空闲内缓冲区红黑树中
static void binder_insert_free_buffer(
	struct binder_proc *proc, struct binder_buffer *new_buffer)
{
	struct rb_node **p = &proc->free_buffers.rb_node;
	struct rb_node *parent = NULL;
	struct binder_buffer *buffer;
	size_t buffer_size;
	size_t new_buffer_size;

	BUG_ON(!new_buffer->free);

	// 计算new_buffer的大小
	new_buffer_size = binder_buffer_size(proc, new_buffer);

	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printk(KERN_INFO "binder: %d: add free buffer, size %zd, "
		       "at %p\n", proc->pid, new_buffer_size, new_buffer);

	while (*p) {
		parent = *p;
		buffer = rb_entry(parent, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);

		buffer_size = binder_buffer_size(proc, buffer);

		if (new_buffer_size < buffer_size)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	// 调用函数rb_link_node和rb_insert_color将内核缓冲区new_buffer保存在这个位置上
	// 这样就相当于将内核缓冲区new_buffer插入到目标进程proc的空闲内核缓冲区红黑树free_buffers中
	rb_link_node(&new_buffer->rb_node, parent, p);
	rb_insert_color(&new_buffer->rb_node, &proc->free_buffers);
	// 一个使用Binder进程间通信机制的进程只有将Binder设备文件银蛇到自己的地址空间
	// Binder才能够为它分配内核缓冲区，以便可以用来传输进程间的数据
	// Binder驱动程序为进程分配的内核缓冲区有两个地址
	// 一个是用户空间地址
	// 另一个是内核空间地址
	// 它们有线程的对应关系
	// 
	// Binder驱动为进程分配的内核缓冲区为一系列物理页面
	// 它们分别被映射到进程的用户地址空间和内核地址空间
	// 当Binder驱动需要将一块数据传输给一个进程时
	// 它就可以先把这块数据保存在为该进程分配的一块内核缓冲区中
	// 然后再把这块内核缓冲区的用户空间地址告诉进程
	// 最后进程就可以访问里面的数据了
	// 这样做的好处就是不需要将内核空间拷贝到用户空间，从而提高了数据的传输效率
}

// 一个进程已分配物理页面的内核缓冲区以它们的[内核空间地址值]作为关键字保存在一个红黑树allocated_buffers中
static void binder_insert_allocated_buffer(
	struct binder_proc *proc, struct binder_buffer *new_buffer)
{
	struct rb_node **p = &proc->allocated_buffers.rb_node;
	struct rb_node *parent = NULL;
	struct binder_buffer *buffer;

	BUG_ON(new_buffer->free);

	// 从里面找到一个合适的位置p
	while (*p) {
		parent = *p;
		buffer = rb_entry(parent, struct binder_buffer, rb_node);
		BUG_ON(buffer->free);

		if (new_buffer < buffer)
			p = &parent->rb_left;
		else if (new_buffer > buffer)
			p = &parent->rb_right;
		else
			BUG();
	}
	// 将已分配了的物理页面内核缓冲区new_buffer添加到目标进程的红黑树allocated_buffer中
	rb_link_node(&new_buffer->rb_node, parent, p);
	rb_insert_color(&new_buffer->rb_node, &proc->allocated_buffers);
}

// 根据用户空间来查询一个内核缓冲区
//
// 将binder_buffer->data所指向的一块数据缓冲区的用户地址传递给目标进程
// user_ptr: 用户空间地址，指向binder_buffer->data的地址
static struct binder_buffer *binder_buffer_lookup(
	struct binder_proc *proc, void __user *user_ptr)
{
	// 已分配内核缓冲区红黑树的父节点
	struct rb_node *n = proc->allocated_buffers.rb_node;
	struct binder_buffer *buffer;
	struct binder_buffer *kern_ptr;

	// 用来计算一个binder_buffer结构体的内核空间地址
	// binder_buffer结构体的用户空间地址 - 目标进程proc成员变量user_buffer_offset
	kern_ptr = user_ptr - proc->user_buffer_offset
		- offsetof(struct binder_buffer, data);

	while (n) {
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(buffer->free);

		if (kern_ptr < buffer)
			n = n->rb_left;
		else if (kern_ptr > buffer)
			n = n->rb_right;
		else
			return buffer;
	}
	return NULL;
}

// 为一段指定的虚拟地址空间分配或者释放物理界面
// proc: 要操作的目标进程
// allocate: 如果等于0，表示要释放物理页面，否则要分配物理页面
// start/end: 指定了要操作的内核地址空间的开始和结束地址
// vma: 指向要映射的用户地址空间
static int binder_update_page_range(struct binder_proc *proc, int allocate,
	void *start, void *end, struct vm_area_struct *vma)
{
	void *page_addr;
	unsigned long user_page_addr;
	struct vm_struct tmp_area;
	struct page **page;
	struct mm_struct *mm;

	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printk(KERN_INFO "binder: %d: %s pages %p-%p\n",
		       proc->pid, allocate ? "allocate" : "free", start, end);

	if (end <= start)
		return 0;

	// 判断vma是否指向一个空的用户地址空间
	// 如果是，就从目标进程proc成员变量获得要映射的地址空间
	if (vma)
		mm = NULL;
	else
		mm = get_task_mm(proc->tsk);

	if (mm) {
		down_write(&mm->mmap_sem);
		vma = proc->vma;
	}

	// 判断是要为内核地址空间start~end分配物理页面还是释放物理页面
	if (allocate == 0)
		goto free_range;

	if (vma == NULL) {
		printk(KERN_ERR "binder: %d: binder_alloc_buf failed to "
		       "map pages in userspace, no vma\n", proc->pid);
		goto err_no_vma;
	}

	// 内核地址空间start~end可能包含了多个页面
	// 使用for循环一次为每一个虚拟地址空间页面分配一个物理页面
	for (page_addr = start; page_addr < end; page_addr += PAGE_SIZE) {
		int ret;
		struct page **page_array_ptr;
		// 首先从目标进程proc的物理页面结构体指针数组pages中获得一个与内核地址空间page_addr~(page_addr+PAGE_SIZE)对应的物理页面指针
		page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];

		BUG_ON(*page);
		// 调用alloc_page为该内核地址空间分配一个物理页面
		*page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (*page == NULL) {
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
			       "for page at %p\n", proc->pid, page_addr);
			goto err_alloc_page_failed;
		}
		// 分配成功后，分别映射到对应的内核地址空间和用户地址空间
		//
		// 映射内核地址空间
		tmp_area.addr = page_addr;
		// 8K用来检测非法指针
		tmp_area.size = PAGE_SIZE + PAGE_SIZE /* guard page? */;
		page_array_ptr = page;
		ret = map_vm_area(&tmp_area, PAGE_KERNEL, &page_array_ptr);
		if (ret) {
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
			       "to map page at %p in kernel\n",
			       proc->pid, page_addr);
			goto err_map_kernel_failed;
		}
		// 映射用户地址空间
		user_page_addr =
			(uintptr_t)page_addr + proc->user_buffer_offset;
		ret = vm_insert_page(vma, user_page_addr, page[0]);
		if (ret) {
			printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
			       "to map page at %lx in userspace\n",
			       proc->pid, user_page_addr);
			goto err_vm_insert_page_failed;
		}
		/* vm_insert_page does not seem to increment the refcount */
	}
	if (mm) {
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
	return 0;

free_range:
	// 物理页面的释放过程
	// start~end包含了多个页面，使用for循环来为每一个虚拟地址空间页面释放物理页面
	for (page_addr = end - PAGE_SIZE; page_addr >= start;
	    page_addr -= PAGE_SIZE) {
		// 先从目标进程proc的物理页面结构体指针数据pages中获得一个
		// 与内核地址空间page_addr~(page_addr+PAGE_SIZE)对应的物理页面指针
		page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
		if (vma)
			// 调用zap_page_range和unmap_kernel_rage来接触该物理页面在用户地址空间和内核地址空间的映射
			zap_page_range(vma, (uintptr_t)page_addr +
				proc->user_buffer_offset, PAGE_SIZE, NULL);
err_vm_insert_page_failed:
		unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
err_map_kernel_failed:
		// 用来释放该物理页面
		__free_page(*page);
		*page = NULL;
err_alloc_page_failed:
		;
	}
err_no_vma:
	if (mm) {
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
	return -ENOMEM;
}

// 开始时，Binder驱动只为进程分配了一个页面的物理内存
// 后面随着进程的需要而分配更多的物理内存，但是最多可以分配4M的内存
// 这是一种按需分配的策略
// 物理内存的分配以页面为单位
// 进程一次使用的内存却不是以页面为单位的
// Binder驱动程序为进程维护了一个内核缓冲区池，每一块内存都使用了一个binder_buffer结构体来描述
// 保存在一个列表中
// Binder驱动程序又将正在使用的内存块，即已经分配了物理页面的内存块
// 以及空闲的内存快，即还有分配物理页面的内存块
// 分别保存在两个红黑树中
// 当正在试用的内存块使用完后，Binder驱动程序就会释放它的物理页面，并且加入到空闲的内核缓冲区红黑树中
// 而当进程需要新的内存块时，Binder驱动程序就从空闲内核缓冲区红黑树中分配一块合适的内核缓冲区
// 并且为它分配物理页面，最后交个进程来使用
// 
// Binder驱动是如何管理进程的内核缓冲区：分配，释放，查询
//
// 当一个进程使用命令协议BC_TRANSACTION或者BC_REPLY向另外一个进程传递数据时
// Binder驱动程序就需要将这些数据从用户空间拷贝到内核空间
// 然后再传递给目标进程
// 这时，Binder驱动就需要在目标进程的内存池中分配出一小块内核缓冲区来保存这些数据
//
// 当一个进程使用命令协议BC_TRANSACTION或者BC_REPLY来与Binder驱动交互时
// 它会从用户空间传递一个binder_transaction_data结构体给Binder驱动程序
// 而在binder_transaction_data结构体中，有一个数据缓冲区和一个偏移数组缓冲区
// 这两个缓冲区都需要拷贝到目标进程的内核缓冲区中
//
// proc: 用来描述目标进程
// data_size: 用来描述数据缓冲区的大小
// offsets_size: 用来描述偏移数组缓冲区的大小
// is_async: 用来描述所请求的内核缓冲区是否是异步事务
static struct binder_buffer *binder_alloc_buf(struct binder_proc *proc,
	size_t data_size, size_t offsets_size, int is_async)
{
	struct rb_node *n = proc->free_buffers.rb_node;
	struct binder_buffer *buffer;
	size_t buffer_size;
	struct rb_node *best_fit = NULL;
	void *has_page_addr;
	void *end_page_addr;
	size_t size;

	if (proc->vma == NULL) {
		printk(KERN_ERR "binder: %d: binder_alloc_buf, no vma\n",
		       proc->pid);
		return NULL;
	}

	// 分别将参数data_size和offsets_size对齐到一个void指针大小边界
	// 然后将它们相加就得到要分配的内核缓冲区大小
	// 保存在变量size中
	size = ALIGN(data_size, sizeof(void *)) +
		ALIGN(offsets_size, sizeof(void *));

	// 检查相加后的size值是否发生溢出
	if (size < data_size || size < offsets_size) {
		binder_user_error("binder: %d: got transaction with invalid "
			"size %zd-%zd\n", proc->pid, data_size, offsets_size);
		return NULL;
	}

	// 驱动程序为进程分配一个大小为size的内核缓冲区来保存数据
	// 还要额外分配一个binder_buffer来描述这个内核缓冲区
	if (is_async &&
	    proc->free_async_space < size + sizeof(struct binder_buffer)) {
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
			printk(KERN_ERR "binder: %d: binder_alloc_buf size %zd f"
			       "ailed, no async space left\n", proc->pid, size);
		return NULL;
	}

	// 使用最佳适配算法在目标进程的空闲内核缓冲区红黑树中检查有没有最合适的内核缓冲区可用
	while (n) {
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);
		buffer_size = binder_buffer_size(proc, buffer);

		if (size < buffer_size) {
			// 如果有，将它保存在变量best_fit中
			best_fit = n;
			n = n->rb_left;
		} else if (size > buffer_size)
			n = n->rb_right;
		else {
			best_fit = n;
			break;
		}
	}
	if (best_fit == NULL) {
		printk(KERN_ERR "binder: %d: binder_alloc_buf size %zd failed, "
		       "no address space\n", proc->pid, size);
		return NULL;
	}
	// 如果n为NULL，那么说明没能从目标进程的空闲内核缓冲区红黑树中找到一块大小刚刚合适的内核缓冲区
	// 但是找到了一块较大的内核缓冲区
	if (n == NULL) {
		buffer = rb_entry(best_fit, struct binder_buffer, rb_node);
		// 计算实际找到的内核缓冲区buffer大小，并且保存在buffer_size
		buffer_size = binder_buffer_size(proc, buffer);
	}
	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printk(KERN_INFO "binder: %d: binder_alloc_buf size %zd got buff"
		       "er %p size %zd\n", proc->pid, size, buffer, buffer_size);

	// 使用宏PAGE_MASK来计算空闲内核缓冲区buffer的结束地址所在的页面的起始地址
	// 保存在has_page_addr中
	has_page_addr =
		(void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK);
	// 因为空闲内核缓冲区buffer大于要求分配的内核缓冲区大小
	// 因此需要对它进行裁剪
	// 裁剪后得到两块小的内核缓冲区
	// 其中一块用来分配，另一块要继续留在目标进程的空闲内核缓冲区红黑树中
	if (n == NULL) {
		if (size + sizeof(struct binder_buffer) + 4 >= buffer_size)
			// 如果裁剪后的第二块缓冲区小于或者等于4个字节，则不对空闲内核缓冲区buffer进行裁剪了
			buffer_size = size; /* no room for other buffers */
		else
			// 如果大于4个字节，那么久需要将它加入到目标进程的空闲内核缓冲区红黑树中
			// 最终将需要分配的内核缓冲区大小保存在buffer_size中
			buffer_size = size + sizeof(struct binder_buffer);
	}
	// PAGE_ALIGN将它的结束地址对齐到页面边界，并保存在变量end_page_addr中
	end_page_addr =
		(void *)PAGE_ALIGN((uintptr_t)buffer->data + buffer_size);
	// 将要分配的内核缓冲区的结束地址对齐到页面界面
	// 对齐之后，得到的地址end_page_addr可能大于原来的空闲内核缓冲区buffer的结束地址has_page_addr
	// 这时将end_page_addr修改为has_page_addr
	// 
	// 三种情况：
	// 1. 空闲内核缓冲区buffer的结束地址刚好对齐到页面边界
	// 2. 空闲内核缓冲区buffer的结束地址没有对齐到页面边界，内核缓冲区的结束地址end_page_addr可能大于或小于has_page_addr
	if (end_page_addr > has_page_addr)
		end_page_addr = has_page_addr;
	// 计算好分配的内核缓冲区的结束地址所在的页面
	// 调用binder_update_page_range为它来分配物理页面
	if (binder_update_page_range(proc, 1,
	    (void *)PAGE_ALIGN((uintptr_t)buffer->data), end_page_addr, NULL))
		return NULL;

	// 首先将空闲内核缓冲区从目标进程的空闲内核缓冲区红黑树中删除
	rb_erase(best_fit, &proc->free_buffers);
	buffer->free = 0;
	// 将前面分配的内核缓冲区加入到目标已分配物理页面的内核缓冲区红黑树中
	binder_insert_allocated_buffer(proc, buffer);
	// 检查从原来的空闲内核缓冲区中分配出来一块新的内核缓冲区之后，是否还有剩余
	if (buffer_size != size) {
		// 如果有，将剩余的内核缓冲区封装成一块新的内核缓冲区new_buffer
		struct binder_buffer *new_buffer = (void *)buffer->data + size;
		// 加入到目标进程的内核缓冲区列表
		list_add(&new_buffer->entry, &buffer->entry);
		new_buffer->free = 1;
		// 加入到空闲内核缓冲区红黑树中
		binder_insert_free_buffer(proc, new_buffer);
	}
	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printk(KERN_INFO "binder: %d: binder_alloc_buf size %zd got "
		       "%p\n", proc->pid, size, buffer);
	// 设置新分配的内核缓冲区的数据缓冲区和偏移数组缓冲区大小
	buffer->data_size = data_size;
	buffer->offsets_size = offsets_size;
	// 设置新分配的内核缓冲区是否用于异步事务
	buffer->async_transaction = is_async;
	if (is_async) {
		// 减少目标进程proc可用于异步事务的内核缓冲区的大小
		proc->free_async_space -= size + sizeof(struct binder_buffer);
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC_ASYNC)
			printk(KERN_INFO "binder: %d: binder_alloc_buf size %zd "
			       "async free %zd\n", proc->pid, size,
			       proc->free_async_space);
	}

	// 将新分配的内核缓冲区返回给调用者
	return buffer;
}

// 由于Binder驱动是以页面大小为单位来分配物理页面的
// 因此，在删除一个空闲缓冲区时，需要找到用来描述它的结构体binder_buffer所在的虚拟地址页面的地址
//
// 当一个binder_buffer结构体横跨两个虚拟地址页面时
// buffer_start_page用来计算第一个虚拟地址页面的地址
// buffer_end_page用来计算第二个虚拟地址页面的地址
//
// 否则，返回的是哦那个一个虚拟地址页面的地址
static void *buffer_start_page(struct binder_buffer *buffer)
{
	// 把一个结构体binder_buffer的地址值与宏PAGE_MASK执行按位与操作，就得到第一个虚拟地址页面的地址
	return (void *)((uintptr_t)buffer & PAGE_MASK);
}

static void *buffer_end_page(struct binder_buffer *buffer)
{
	// 由于参数buffer是一个binder_buffer结构体指针
	// 加1之后，就把它向前移动了一个binder_buffer结构体大小，即得到这个binder_buffer结构体的末尾地址
	return (void *)(((uintptr_t)(buffer + 1) - 1) & PAGE_MASK);
}

// 在删除一个binder_buffer结构体buffer时，必须保证它指向的内核缓冲区不是目标进程的第一个缓冲区
// 并且该内核缓冲区以及它前面的内核缓冲区都是空闲的，否则函数就会报错
// 我们假设binder_buffer结构体prev和next分别指向要删除的内核缓冲区的前面一个内核缓冲区和后面一个缓冲区
static void binder_delete_free_buffer(
	struct binder_proc *proc, struct binder_buffer *buffer)
{
	struct binder_buffer *prev, *next = NULL;
	// 要释放的结构体binder_buffer所横跨的第一个虚拟地址页面和第二个虚拟地址页面所对应的物理页面
	// 会根据情况调整变量的值，以便可以正确地删除binder_buffer结构体buffer
	int free_page_end = 1;
	int free_page_start = 1;

	BUG_ON(proc->buffers.next == &buffer->entry);
	prev = list_entry(buffer->entry.prev, struct binder_buffer, entry);
	BUG_ON(!prev->free);
	// 如果binder_buffer结构体buffer的第一个虚拟地址界面和binder_buffer结构体prev的第二个虚拟地址界面
	// 是同一个页面
	// 那么binder_buffer结构体buffer所在的第一个讯地址页面所对应的物理页面就不可以释放
	if (buffer_end_page(prev) == buffer_start_page(buffer)) {
		free_page_start = 0;
		if (buffer_end_page(prev) == buffer_end_page(buffer))
			// binder_buffer结构体buffer和prev同时位于同一个虚拟地址中
			free_page_end = 0;
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
			printk(KERN_INFO "binder: %d: merge free, buffer %p "
			       "share page with %p\n", proc->pid, buffer, prev);
	}

	if (!list_is_last(&buffer->entry, &proc->buffers)) {
		next = list_entry(buffer->entry.next,
				  struct binder_buffer, entry);
		if (buffer_start_page(next) == buffer_end_page(buffer)) {
			// 如果binder_buffer结构体buffer的第二个虚拟地址页面和binder_buffer结构体next的
			// 第一个虚拟地址页面是同一个页面，那么binder_buffer结构体buffer所在的第二个虚拟地址就不可以
			// 释放
			free_page_end = 0;
			if (buffer_start_page(next) ==
			    buffer_start_page(buffer))
			    // binder_buffer结构体buffer和next同时位于一个虚拟地址页面中
				free_page_start = 0;
			if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
				printk(KERN_INFO "binder: %d: merge free, "
				       "buffer %p share page with %p\n",
				       proc->pid, buffer, prev);
		}
	}
	// 调整好free_page_start和free_page_end值后
	// 首先将binder_buffer结构体buffer所描述的内核缓冲区从目标进程proc的内核缓冲区列表中删除
	list_del(&buffer->entry);
	// 如果free_page_start或free_page_end有一个值为1
	// 就需要释放它所在的虚拟页面所对应的物理页面
	if (free_page_start || free_page_end) {
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
			printk(KERN_INFO "binder: %d: merge free, buffer %p do "
			       "not share page%s%s with with %p or %p\n",
			       proc->pid, buffer, free_page_start ? "" : " end",
			       free_page_end ? "" : " start", prev, next);
		binder_update_page_range(proc, 0, free_page_start ?
			buffer_start_page(buffer) : buffer_end_page(buffer),
			(free_page_end ? buffer_end_page(buffer) :
			buffer_start_page(buffer)) + PAGE_SIZE, NULL);
	}
}

// 返回协议BR_TRANSACTION或者BR_REPLY之后，使用命令协议BC_FREE_BUFFER来通知Binder驱动释放相应的内核缓冲区
// 以免浪费系统内存
static void binder_free_buf(
	struct binder_proc *proc, struct binder_buffer *buffer)
{
	size_t size, buffer_size;

	// 计算要释放的内核缓冲区buffer的大小
	buffer_size = binder_buffer_size(proc, buffer);

	// 计算它的数据缓冲去以及偏移数组缓冲区的大小，保存在size中
	size = ALIGN(buffer->data_size, sizeof(void *)) +
		ALIGN(buffer->offsets_size, sizeof(void *));
	if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
		printk(KERN_INFO "binder: %d: binder_free_buf %p size %zd buffer"
		       "_size %zd\n", proc->pid, buffer, size, buffer_size);

	BUG_ON(buffer->free);
	BUG_ON(size > buffer_size);
	BUG_ON(buffer->transaction != NULL);
	BUG_ON((void *)buffer < proc->buffer);
	BUG_ON((void *)buffer > proc->buffer + proc->buffer_size);

	if (buffer->async_transaction) {
		// 如果是用于处理异步事务的，将它所占用的大小增加到目标进程proc可用于异步事务的内核缓冲区大小free_async_space中
		proc->free_async_space += size + sizeof(struct binder_buffer);
		if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC_ASYNC)
			printk(KERN_INFO "binder: %d: binder_free_buf size %zd "
			       "async free %zd\n", proc->pid, size,
			       proc->free_async_space);
	}

	// 释放 内核缓冲区buffer用来保存数据的那一部分地址空间所占有的物理页面
	binder_update_page_range(proc, 0,
		(void *)PAGE_ALIGN((uintptr_t)buffer->data),
		(void *)(((uintptr_t)buffer->data + buffer_size) & PAGE_MASK),
		NULL);
	// 从目标进程proc的已分配物理页面的内核缓冲区红黑树中删除
	rb_erase(&buffer->rb_node, &proc->allocated_buffers);
	buffer->free = 1;
	if (!list_is_last(&buffer->entry, &proc->buffers)) {
		// 如果buffer不是目标进程proc内核缓冲区列表中的最后一个元素
		// 并且它前后的内核缓冲区也是空闲的
		// 那么就需要将它们合并成一个更大的空闲内核缓冲区
		//
		// 合并内核缓冲区buffer
		// 合并后的内核缓冲区保存在变量buffer中
		struct binder_buffer *next = list_entry(buffer->entry.next,
						struct binder_buffer, entry);
		if (next->free) {
			rb_erase(&next->rb_node, &proc->free_buffers);
			binder_delete_free_buffer(proc, next);
		}
	}
	if (proc->buffers.next != &buffer->entry) {
		struct binder_buffer *prev = list_entry(buffer->entry.prev,
						struct binder_buffer, entry);
		if (prev->free) {
			binder_delete_free_buffer(proc, buffer);
			rb_erase(&prev->rb_node, &proc->free_buffers);
			buffer = prev;
		}
	}
	// 将它添加到目标进程proc空闲内核缓冲区红黑树中
	binder_insert_free_buffer(proc, buffer);
}

// 根据一个用户空间地址ptr在目标进程proc中找到一个对应的Binder实体对象
// Binder实体对象的关键字是ptr，保存在红黑树nodes中
// 在目标进程proc的Binder实体对象红黑树nodes中检查是否存在一个与参数ptr对应的Binder实体对象
static struct binder_node *
binder_get_node(struct binder_proc *proc, void __user *ptr)
{
	struct rb_node *n = proc->nodes.rb_node;
	struct binder_node *node;

	while (n) {
		node = rb_entry(n, struct binder_node, rb_node);

		if (ptr < node->ptr)
			n = n->rb_left;
		else if (ptr > node->ptr)
			n = n->rb_right;
		else
			return node;
	}
	return NULL;
}

// proc: 用来描述service manager进程
// ptr, cookie: 描述一个Binder本地对象
static struct binder_node *
binder_new_node(struct binder_proc *proc, void __user *ptr, void __user *cookie)
{
	struct rb_node **p = &proc->nodes.rb_node;
	struct rb_node *parent = NULL;
	struct binder_node *node;

	// 查询是否在已有的红黑树已经创建过Binder实体对象
	while (*p) {
		parent = *p;
		node = rb_entry(parent, struct binder_node, rb_node);

		if (ptr < node->ptr)
			p = &(*p)->rb_left;
		else if (ptr > node->ptr)
			p = &(*p)->rb_right;
		else
			return NULL;
	}

	// 没有查询到，创建一个新的实体对象
	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (node == NULL)
		return NULL;
	binder_stats.obj_created[BINDER_STAT_NODE]++;
	rb_link_node(&node->rb_node, parent, p);
	rb_insert_color(&node->rb_node, &proc->nodes);
	node->debug_id = ++binder_last_id;
	node->proc = proc;
	node->ptr = ptr;
	node->cookie = cookie;
	node->work.type = BINDER_WORK_NODE;
	INIT_LIST_HEAD(&node->work.entry);
	INIT_LIST_HEAD(&node->async_todo);
	if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
		printk(KERN_INFO "binder: %d:%d node %d u%p c%p created\n",
		       proc->pid, current->pid, node->debug_id,
		       node->ptr, node->cookie);
	return node;
}

// Binder实体对象是一个类型为binder_node的对象
// 在驱动中创建，被Binder驱动程序中的Binder引用对象所引用
// 当Client进程第一次引用一个Binder实体对象时，Binder驱动会在内部创建一个Binder引用对象
// 例如，当Client进程通过Service Manager来获得一个Service组件时
// Binder驱动会找到与该Service组件对应的Binder实体对象
// 接着再创建一个Binder引用对象来引用它
// 这时需要增加被引用的Binder实体对象的引用计数
// 相应的
// 当Client进程不再引用一个Service组件时，它也会请求Binder驱动释放之前为它创建一个Binder引用对象
// 这时就需要减少该Binder引用对象所引用的实体对象的引用计数
//
// node: 增加引用计数的实体对象
// strong: 增加强引用计数还是弱引用计数
// internel: 内部引用还是外部引用
// target_list: 目标进程或线程的todo队列,不为NULL时表示增加Binder实体对象node之后也要相应的增加Binder本地对象的引用计数
//
// 当Client进程通过一个Binder引用对象来引用一个Binder实体对象时
// Binder驱动会增加它的外部引用对象
// 同时为了避免Binder实体对象被过早的销毁
static int
binder_inc_node(struct binder_node *node, int strong, int internal,
		struct list_head *target_list)
{
	if (strong) {
		if (internal) {
			// 需要增加Binder实体对象node的外部强引用计数
			if (target_list == NULL &&
			    node->internal_strong_refs == 0 &&
			    !(node == binder_context_mgr_node &&
			    node->has_strong_ref)) {
				printk(KERN_ERR "binder: invalid inc strong "
					"node for %d\n", node->debug_id);
				return -EINVAL;
			}
			node->internal_strong_refs++;
		} else
			// 增加Binder实体对象node的内部强引用计数
			node->local_strong_refs++;
		if (!node->has_strong_ref && target_list) {
			list_del_init(&node->work.entry);
			list_add_tail(&node->work.entry, target_list);
		}
	} else {
		if (!internal)
			node->local_weak_refs++;
		// 在调用binder_inc_node之前，已经将一个对应的Binder引用对象添加到Binder实体对象noe的Binder引用对象列表中
		// 增加了Binder实体对象node的外部弱引用计数
		if (!node->has_weak_ref && list_empty(&node->work.entry)) {
			if (target_list == NULL) {
				printk(KERN_ERR "binder: invalid inc weak node "
					"for %d\n", node->debug_id);
				return -EINVAL;
			}
			list_add_tail(&node->work.entry, target_list);
		}
	}
	return 0;
}

// 减少Binder实体对象的引用计数
// node: 要减少的引用计数Binder实体对象
// strong: 是否要减少强引用计数
// internal: 是否减少内部引用计数
static int
binder_dec_node(struct binder_node *node, int strong, int internal)
{
	if (strong) {
		if (internal)
			// 减少外部强引用计数
			node->internal_strong_refs--;
		else
			// 减少内部强引用
			node->local_strong_refs--;
		if (node->local_strong_refs || node->internal_strong_refs)
			return 0;
	} else {
		if (!internal)
			node->local_weak_refs--;
		if (node->local_weak_refs || !hlist_empty(&node->refs))
			return 0;
	}
	if (node->proc && (node->has_strong_ref || node->has_weak_ref)) {
		// Binder实体对象node的强引用或者弱引用计数等于0
		if (list_empty(&node->work.entry)) {
			// 减少Binder实体对象node对应的Binder本地对象的强引用计数或者弱引用计数
			list_add_tail(&node->work.entry, &node->proc->todo);
			wake_up_interruptible(&node->proc->wait);
		}
	} else {
		// 要么Binder实体对象node的宿主进程结构体为NULL，要么成员变量has_strong_ref和has_weak_ref都等于0
		if (hlist_empty(&node->refs) && !node->local_strong_refs &&
		    !node->local_weak_refs) {
			// 如果Binder实体对象node的所有引用计数都等于0
			// 那么将要销毁Binder实体对象node
			list_del_init(&node->work.entry);
			if (node->proc) {
				// 如果宿主对象不为空，说明它保存在实体对象红黑树中
				// 将会把它从红黑树中删除
				rb_erase(&node->rb_node, &node->proc->nodes);
				if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
					printk(KERN_INFO "binder: refless node %d deleted\n", node->debug_id);
			} else {
				// 如果宿主进程结构体为NULL
				// 那么实体对象node保存在死亡Binder实体对象列表中
				hlist_del(&node->dead_node);
				if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
					printk(KERN_INFO "binder: dead node %d deleted\n", node->debug_id);
			}
			// 最后调用kfree来销毁Binder实体对象
			kfree(node);
			binder_stats.obj_deleted[BINDER_STAT_NODE]++;
		}
	}

	return 0;
}


static struct binder_ref *
binder_get_ref(struct binder_proc *proc, uint32_t desc)
{
	struct rb_node *n = proc->refs_by_desc.rb_node;
	struct binder_ref *ref;

	while (n) {
		ref = rb_entry(n, struct binder_ref, rb_node_desc);

		if (desc < ref->desc)
			n = n->rb_left;
		else if (desc > ref->desc)
			n = n->rb_right;
		else
			return ref;
	}
	return NULL;
}

static struct binder_ref *
binder_get_ref_for_node(struct binder_proc *proc, struct binder_node *node)
{
	struct rb_node *n;
	struct rb_node **p = &proc->refs_by_node.rb_node;
	struct rb_node *parent = NULL;
	struct binder_ref *ref, *new_ref;

	// 首先判断是否已经在目标进程proc中为Binder实体对象node创建过一个Binder引用对象
	while (*p) {
		parent = *p;
		ref = rb_entry(parent, struct binder_ref, rb_node_node);

		if (node < ref->node)
			p = &(*p)->rb_left;
		else if (node > ref->node)
			p = &(*p)->rb_right;
		else
			return ref;
	}
	// 为proc创建一个Binder引用对象new_ref
	new_ref = kzalloc(sizeof(*ref), GFP_KERNEL);
	if (new_ref == NULL)
		return NULL;
	binder_stats.obj_created[BINDER_STAT_REF]++;
	new_ref->debug_id = ++binder_last_id;
	new_ref->proc = proc;
	new_ref->node = node;
	// 将引用添加到红黑树refs_by_node中
	rb_link_node(&new_ref->rb_node_node, parent, p);
	rb_insert_color(&new_ref->rb_node_node, &proc->refs_by_node);

	// 为新创建的Binder引用对象new_ref分配句柄值
	// 检查是否引用了service manager的Binder实体对象binder_context_mgr_node
	new_ref->desc = (node == binder_context_mgr_node) ? 0 : 1;
	for (n = rb_first(&proc->refs_by_desc); n != NULL; n = rb_next(n)) {
		// 在proc中找到一个未使用的最小句柄值作为新创建的Binder引用对象new_ref的句柄值
		ref = rb_entry(n, struct binder_ref, rb_node_desc);
		if (ref->desc > new_ref->desc)
			break;
		new_ref->desc = ref->desc + 1;
	}

	p = &proc->refs_by_desc.rb_node;
	// 在此确认前面为Binder引用对象new_ref分配的句柄值是有效的
	while (*p) {
		parent = *p;
		ref = rb_entry(parent, struct binder_ref, rb_node_desc);

		if (new_ref->desc < ref->desc)
			p = &(*p)->rb_left;
		else if (new_ref->desc > ref->desc)
			p = &(*p)->rb_right;
		else
			BUG();
	}
	// 将Binder引用对象new_ref添加到目标进程proc的红黑树refs_by_desc中
	rb_link_node(&new_ref->rb_node_desc, parent, p);
	rb_insert_color(&new_ref->rb_node_desc, &proc->refs_by_desc);
	// 将new_ref添加到它所引用的Binder实体对象node的Binder引用对象列表中
	if (node) {
		hlist_add_head(&new_ref->node_entry, &node->refs);
		if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
			printk(KERN_INFO "binder: %d new ref %d desc %d for "
				"node %d\n", proc->pid, new_ref->debug_id,
				new_ref->desc, node->debug_id);
	} else {
		if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
			printk(KERN_INFO "binder: %d new ref %d desc %d for "
				"dead node\n", proc->pid, new_ref->debug_id,
				new_ref->desc);
	}
	return new_ref;
}

static void
binder_delete_ref(struct binder_ref *ref)
{
	if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
		printk(KERN_INFO "binder: %d delete ref %d desc %d for "
			"node %d\n", ref->proc->pid, ref->debug_id,
			ref->desc, ref->node->debug_id);
	// 将ref从宿主进程中的两个红黑树中移除
	rb_erase(&ref->rb_node_desc, &ref->proc->refs_by_desc);
	rb_erase(&ref->rb_node_node, &ref->proc->refs_by_node);
	// 如果是被强行移除的，即强引用计数还大于0的情况
	if (ref->strong)
		// 调用函数binder_dec_node来减少它引用的Binder实体对象的外部强引用计数
		binder_dec_node(ref->node, 1, 1);
	// 一个Binder引用对象还保存在它所引用的Binder实体对象的Binder引用对象列表中
	// 因此需要进行移出
	hlist_del(&ref->node_entry);
	// 减少一个即将销毁的Binder引用对象所引用的Binder实体对象的外部弱引用计数
	binder_dec_node(ref->node, 0, 1);
	// 是否注册了一个死亡接受通知
	if (ref->death) {
		if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
			printk(KERN_INFO "binder: %d delete ref %d desc %d "
				"has death notification\n", ref->proc->pid,
				ref->debug_id, ref->desc);
		// 如果是，那么久删除以及销毁该死亡接受通知
		list_del(&ref->death->work.entry);
		kfree(ref->death);
		binder_stats.obj_deleted[BINDER_STAT_DEATH]++;
	}
	// 销毁Binder的引用对象
	kfree(ref);
	binder_stats.obj_deleted[BINDER_STAT_REF]++;
}

static int
binder_inc_ref(
	struct binder_ref *ref, int strong, struct list_head *target_list)
{
	int ret;
	if (strong) {
		if (ref->strong == 0) {
			ret = binder_inc_node(ref->node, 1, 1, target_list);
			if (ret)
				return ret;
		}
		ref->strong++;
	} else {
		if (ref->weak == 0) {
			ret = binder_inc_node(ref->node, 0, 1, target_list);
			if (ret)
				return ret;
		}
		ref->weak++;
	}
	return 0;
}


static int
binder_dec_ref(struct binder_ref *ref, int strong)
{
	if (strong) {
		if (ref->strong == 0) {
			binder_user_error("binder: %d invalid dec strong, "
					  "ref %d desc %d s %d w %d\n",
					  ref->proc->pid, ref->debug_id,
					  ref->desc, ref->strong, ref->weak);
			return -EINVAL;
		}
		ref->strong--;
		if (ref->strong == 0) {
			int ret;
			ret = binder_dec_node(ref->node, strong, 1);
			if (ret)
				return ret;
		}
	} else {
		if (ref->weak == 0) {
			binder_user_error("binder: %d invalid dec weak, "
					  "ref %d desc %d s %d w %d\n",
					  ref->proc->pid, ref->debug_id,
					  ref->desc, ref->strong, ref->weak);
			return -EINVAL;
		}
		ref->weak--;
	}
	// 当强引用和弱引用计数都为0时，此时调用binder_delete_ref删除该binder_ref
	if (ref->strong == 0 && ref->weak == 0)
		binder_delete_ref(ref);
	return 0;
}

static void
binder_pop_transaction(
	struct binder_thread *target_thread, struct binder_transaction *t)
{
	if (target_thread) {
		BUG_ON(target_thread->transaction_stack != t);
		BUG_ON(target_thread->transaction_stack->from != target_thread);
		target_thread->transaction_stack =
			target_thread->transaction_stack->from_parent;
		t->from = NULL;
	}
	t->need_reply = 0;
	if (t->buffer)
		t->buffer->transaction = NULL;
	kfree(t);
	binder_stats.obj_deleted[BINDER_STAT_TRANSACTION]++;
}

static void
binder_send_failed_reply(struct binder_transaction *t, uint32_t error_code)
{
	struct binder_thread *target_thread;
	BUG_ON(t->flags & TF_ONE_WAY);
	while (1) {
		target_thread = t->from;
		if (target_thread) {
			if (target_thread->return_error != BR_OK &&
			   target_thread->return_error2 == BR_OK) {
				target_thread->return_error2 =
					target_thread->return_error;
				target_thread->return_error = BR_OK;
			}
			if (target_thread->return_error == BR_OK) {
				if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
					printk(KERN_INFO "binder: send failed reply for transaction %d to %d:%d\n",
					       t->debug_id, target_thread->proc->pid, target_thread->pid);

				binder_pop_transaction(target_thread, t);
				target_thread->return_error = error_code;
				wake_up_interruptible(&target_thread->wait);
			} else {
				printk(KERN_ERR "binder: reply failed, target "
					"thread, %d:%d, has error code %d "
					"already\n", target_thread->proc->pid,
					target_thread->pid,
					target_thread->return_error);
			}
			return;
		} else {
			struct binder_transaction *next = t->from_parent;

			if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
				printk(KERN_INFO "binder: send failed reply "
					"for transaction %d, target dead\n",
					t->debug_id);

			binder_pop_transaction(target_thread, t);
			if (next == NULL) {
				if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
					printk(KERN_INFO "binder: reply failed,"
						" no target thread at root\n");
				return;
			}
			t = next;
			if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
				printk(KERN_INFO "binder: reply failed, no targ"
					"et thread -- retry %d\n", t->debug_id);
		}
	}
}

static void
binder_transaction_buffer_release(struct binder_proc *proc,
			struct binder_buffer *buffer, size_t *failed_at);

static void
binder_transaction(struct binder_proc *proc, struct binder_thread *thread,
	struct binder_transaction_data *tr, int reply)
{
	struct binder_transaction *t;
	struct binder_work *tcomplete;
	size_t *offp, *off_end;
	struct binder_proc *target_proc;
	struct binder_thread *target_thread = NULL;
	struct binder_node *target_node = NULL;
	struct list_head *target_list;
	wait_queue_head_t *target_wait;
	struct binder_transaction *in_reply_to = NULL;
	struct binder_transaction_log_entry *e;
	uint32_t return_error;

	e = binder_transaction_log_add(&binder_transaction_log);
	e->call_type = reply ? 2 : !!(tr->flags & TF_ONE_WAY);
	e->from_proc = proc->pid;
	e->from_thread = thread->pid;
	e->target_handle = tr->target.handle;
	e->data_size = tr->data_size;
	e->offsets_size = tr->offsets_size;

	if (reply) {
		in_reply_to = thread->transaction_stack;
		if (in_reply_to == NULL) {
			binder_user_error("binder: %d:%d got reply transaction "
					  "with no transaction stack\n",
					  proc->pid, thread->pid);
			return_error = BR_FAILED_REPLY;
			goto err_empty_call_stack;
		}
		binder_set_nice(in_reply_to->saved_priority);
		if (in_reply_to->to_thread != thread) {
			binder_user_error("binder: %d:%d got reply transaction "
				"with bad transaction stack,"
				" transaction %d has target %d:%d\n",
				proc->pid, thread->pid, in_reply_to->debug_id,
				in_reply_to->to_proc ?
				in_reply_to->to_proc->pid : 0,
				in_reply_to->to_thread ?
				in_reply_to->to_thread->pid : 0);
			return_error = BR_FAILED_REPLY;
			in_reply_to = NULL;
			goto err_bad_call_stack;
		}
		thread->transaction_stack = in_reply_to->to_parent;
		target_thread = in_reply_to->from;
		if (target_thread == NULL) {
			return_error = BR_DEAD_REPLY;
			goto err_dead_binder;
		}
		if (target_thread->transaction_stack != in_reply_to) {
			binder_user_error("binder: %d:%d got reply transaction "
				"with bad target transaction stack %d, "
				"expected %d\n",
				proc->pid, thread->pid,
				target_thread->transaction_stack ?
				target_thread->transaction_stack->debug_id : 0,
				in_reply_to->debug_id);
			return_error = BR_FAILED_REPLY;
			in_reply_to = NULL;
			target_thread = NULL;
			goto err_dead_binder;
		}
		target_proc = target_thread->proc;
	// 处理binder_transaction命令协议
	} else {
		if (tr->target.handle) {
			struct binder_ref *ref;
			// 获取引用对象
			ref = binder_get_ref(proc, tr->target.handle);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d got "
					"transaction to invalid handle\n",
					proc->pid, thread->pid);
				return_error = BR_FAILED_REPLY;
				goto err_invalid_target_handle;
			}
			// 获取实体对象
			target_node = ref->node;
			// handle为0时
		} else {
			// 获得service manager实体对象
			target_node = binder_context_mgr_node;
			if (target_node == NULL) {
				return_error = BR_DEAD_REPLY;
				goto err_no_context_mgr_node;
			}
		}
		e->to_node = target_node->debug_id;
		// 找到target_proc
		target_proc = target_node->proc;
		// 找到后接下来要由目标进程空闲线程处理BR_TRANSACTION
		// 空闲线程的类型:
		// 1. 无事可做而空闲
		// 2. 不是真的空闲，处于某个事务过程中，需要等待其它线程来处理另外一个事务
		if (target_proc == NULL) {
			return_error = BR_DEAD_REPLY;
			goto err_dead_binder;
		}
		// 对空闲线程使用做的优化
		// 尝试找到第二种类型的空闲线程来处理BR_TRANSACTION,以便提高目标进程target_proc的进程间通信并发能力
		// 只有当同步时才能执行该优化方案
		if (!(tr->flags & TF_ONE_WAY) && thread->transaction_stack) {
			struct binder_transaction *tmp;
			tmp = thread->transaction_stack;
			if (tmp->to_thread != thread) {
				binder_user_error("binder: %d:%d got new "
					"transaction with bad transaction stack"
					", transaction %d has target %d:%d\n",
					proc->pid, thread->pid, tmp->debug_id,
					tmp->to_proc ? tmp->to_proc->pid : 0,
					tmp->to_thread ?
					tmp->to_thread->pid : 0);
				return_error = BR_FAILED_REPLY;
				goto err_bad_call_stack;
			}
			while (tmp) {
				if (tmp->from && tmp->from->proc == target_proc)
					// 找到处理的线程
					target_thread = tmp->from;
				tmp = tmp->from_parent;
			}
		}
	}
	if (target_thread) {
		// 成功的找到了目标线程
		e->to_thread = target_thread->pid;
		// 指向target_thread的todo队列和wait等待队列
		target_list = &target_thread->todo;
		target_wait = &target_thread->wait;
	} else {
		target_list = &target_proc->todo;
		target_wait = &target_proc->wait;
	}
	e->to_proc = target_proc->pid;

	/* TODO: reuse incoming transaction for reply */
	// 分配了一个binder_transaction结构体t
	// 封装成一个BINDER_WORK_TRANSACTION类型的工作项加入目标todo队列target_list
	// 以便目标线程可以接受到BR_TRANSACTION返回协议
	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (t == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_alloc_t_failed;
	}
	binder_stats.obj_created[BINDER_STAT_TRANSACTION]++;

	// 分配了一个binder_work结构体tcomplete
	tcomplete = kzalloc(sizeof(*tcomplete), GFP_KERNEL);
	if (tcomplete == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_alloc_tcomplete_failed;
	}
	binder_stats.obj_created[BINDER_STAT_TRANSACTION_COMPLETE]++;

	t->debug_id = ++binder_last_id;
	e->debug_id = t->debug_id;

	if (binder_debug_mask & BINDER_DEBUG_TRANSACTION) {
		if (reply)
			printk(KERN_INFO "binder: %d:%d BC_REPLY %d -> %d:%d, "
			       "data %p-%p size %zd-%zd\n",
			       proc->pid, thread->pid, t->debug_id,
			       target_proc->pid, target_thread->pid,
			       tr->data.ptr.buffer, tr->data.ptr.offsets,
			       tr->data_size, tr->offsets_size);
		else
			printk(KERN_INFO "binder: %d:%d BC_TRANSACTION %d -> "
			       "%d - node %d, data %p-%p size %zd-%zd\n",
			       proc->pid, thread->pid, t->debug_id,
			       target_proc->pid, target_node->debug_id,
			       tr->data.ptr.buffer, tr->data.ptr.offsets,
			       tr->data_size, tr->offsets_size);
	}

	// 初始化前面分配的binder_transaction结构体
	if (!reply && !(tr->flags & TF_ONE_WAY))
		// 如果函数正在处理一个BC_TRANSACTION命令协议，并且是所描述的一个同步进程间通信请求
		// 将from指向源线程的thread
		// 以便目标进程target_proc或者目标线程target_thread处理完该进程间通信请求之后，能够找回发出该进程间通信请求的线程
		// 最终返回结果给它
		t->from = thread;
	else
		t->from = NULL;
	t->sender_euid = proc->tsk->cred->euid;
	t->to_proc = target_proc;
	t->to_thread = target_thread;
	t->code = tr->code;
	t->flags = tr->flags;
	t->priority = task_nice(current);
	t->buffer = binder_alloc_buf(target_proc, tr->data_size,
		tr->offsets_size, !reply && (t->flags & TF_ONE_WAY));
	if (t->buffer == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_binder_alloc_buf_failed;
	}
	t->buffer->allow_user_free = 0;
	t->buffer->debug_id = t->debug_id;
	t->buffer->transaction = t;
	t->buffer->target_node = target_node;
	if (target_node)
		// 增加目标Binder实体对象的强引用计数
		binder_inc_node(target_node, 1, 0, NULL);

	offp = (size_t *)(t->buffer->data + ALIGN(tr->data_size, sizeof(void *)));

	// 将数据缓冲区发送拷贝到结构体t的内核缓冲区
	if (copy_from_user(t->buffer->data, tr->data.ptr.buffer, tr->data_size)) {
		binder_user_error("binder: %d:%d got transaction with invalid "
			"data ptr\n", proc->pid, thread->pid);
		return_error = BR_FAILED_REPLY;
		goto err_copy_data_failed;
	}
	// 将偏移数组的内容拷贝到分配给binder_transaction结构体t的内核缓冲区
	if (copy_from_user(offp, tr->data.ptr.offsets, tr->offsets_size)) {
		binder_user_error("binder: %d:%d got transaction with invalid "
			"offsets ptr\n", proc->pid, thread->pid);
		return_error = BR_FAILED_REPLY;
		goto err_copy_data_failed;
	}
	if (!IS_ALIGNED(tr->offsets_size, sizeof(size_t))) {
		binder_user_error("binder: %d:%d got transaction with "
			"invalid offsets size, %zd\n",
			proc->pid, thread->pid, tr->offsets_size);
		return_error = BR_FAILED_REPLY;
		goto err_bad_offset;
	}
	off_end = (void *)offp + tr->offsets_size;
	// 依次处理进程间通信数据中的Binder对象
	for (; offp < off_end; offp++) {
		struct flat_binder_object *fp;
		if (*offp > t->buffer->data_size - sizeof(*fp) ||
		    t->buffer->data_size < sizeof(*fp) ||
		    !IS_ALIGNED(*offp, sizeof(void *))) {
			binder_user_error("binder: %d:%d got transaction with "
				"invalid offset, %zd\n",
				proc->pid, thread->pid, *offp);
			return_error = BR_FAILED_REPLY;
			goto err_bad_offset;
		}
		fp = (struct flat_binder_object *)(t->buffer->data + *offp);
		switch (fp->type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct binder_ref *ref;
			struct binder_node *node = binder_get_node(proc, fp->binder);
			if (node == NULL) {
				// 创建一个Binder实体对象node
				node = binder_new_node(proc, fp->binder, fp->cookie);
				if (node == NULL) {
					return_error = BR_FAILED_REPLY;
					goto err_binder_new_node_failed;
				}
				// 根据从用户空间传递进程的flat_binder_object结构体内容来设置它的最小线程优先级以及是否接受文件描述符标志
				node->min_priority = fp->flags & FLAT_BINDER_FLAG_PRIORITY_MASK;
				node->accept_fds = !!(fp->flags & FLAT_BINDER_FLAG_ACCEPTS_FDS);
			}
			if (fp->cookie != node->cookie) {
				binder_user_error("binder: %d:%d sending u%p "
					"node %d, cookie mismatch %p != %p\n",
					proc->pid, thread->pid,
					fp->binder, node->debug_id,
					fp->cookie, node->cookie);
				goto err_binder_get_ref_for_node_failed;
			}
			// 创建一个Binder引用对象
			ref = binder_get_ref_for_node(target_proc, node);
			if (ref == NULL) {
				return_error = BR_FAILED_REPLY;
				goto err_binder_get_ref_for_node_failed;
			}
			if (fp->type == BINDER_TYPE_BINDER)
				// 修改结构体fp的类型
				// 当驱动将进程间数据传递到目标进程时，进程间通信数据中的Binder实体对象就变成了Binder引用对象
				fp->type = BINDER_TYPE_HANDLE;
			else
				fp->type = BINDER_TYPE_WEAK_HANDLE;
			fp->handle = ref->desc;
			// 增加引用对象ref的引用计数
			binder_inc_ref(ref, fp->type == BINDER_TYPE_HANDLE, &thread->todo);
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printk(KERN_INFO "        node %d u%p -> ref %d desc %d\n",
				       node->debug_id, node->ptr, ref->debug_id, ref->desc);
		} break;
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct binder_ref *ref = binder_get_ref(proc, fp->handle);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d got "
					"transaction with invalid "
					"handle, %ld\n", proc->pid,
					thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_binder_get_ref_failed;
			}
			if (ref->node->proc == target_proc) {
				if (fp->type == BINDER_TYPE_HANDLE)
					fp->type = BINDER_TYPE_BINDER;
				else
					fp->type = BINDER_TYPE_WEAK_BINDER;
				fp->binder = ref->node->ptr;
				fp->cookie = ref->node->cookie;
				binder_inc_node(ref->node, fp->type == BINDER_TYPE_BINDER, 0, NULL);
				if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
					printk(KERN_INFO "        ref %d desc %d -> node %d u%p\n",
					       ref->debug_id, ref->desc, ref->node->debug_id, ref->node->ptr);
			} else {
				struct binder_ref *new_ref;
				new_ref = binder_get_ref_for_node(target_proc, ref->node);
				if (new_ref == NULL) {
					return_error = BR_FAILED_REPLY;
					goto err_binder_get_ref_for_node_failed;
				}
				fp->handle = new_ref->desc;
				binder_inc_ref(new_ref, fp->type == BINDER_TYPE_HANDLE, NULL);
				if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
					printk(KERN_INFO "        ref %d desc %d -> ref %d desc %d (node %d)\n",
					       ref->debug_id, ref->desc, new_ref->debug_id, new_ref->desc, ref->node->debug_id);
			}
		} break;

		case BINDER_TYPE_FD: {
			int target_fd;
			struct file *file;

			if (reply) {
				if (!(in_reply_to->flags & TF_ACCEPT_FDS)) {
					binder_user_error("binder: %d:%d got reply with fd, %ld, but target does not allow fds\n",
						proc->pid, thread->pid, fp->handle);
					return_error = BR_FAILED_REPLY;
					goto err_fd_not_allowed;
				}
			} else if (!target_node->accept_fds) {
				binder_user_error("binder: %d:%d got transaction with fd, %ld, but target does not allow fds\n",
					proc->pid, thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_fd_not_allowed;
			}

			file = fget(fp->handle);
			if (file == NULL) {
				binder_user_error("binder: %d:%d got transaction with invalid fd, %ld\n",
					proc->pid, thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_fget_failed;
			}
			target_fd = task_get_unused_fd_flags(target_proc, O_CLOEXEC);
			if (target_fd < 0) {
				fput(file);
				return_error = BR_FAILED_REPLY;
				goto err_get_unused_fd_failed;
			}
			task_fd_install(target_proc, target_fd, file);
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printk(KERN_INFO "        fd %ld -> %d\n", fp->handle, target_fd);
			/* TODO: fput? */
			fp->handle = target_fd;
		} break;

		default:
			binder_user_error("binder: %d:%d got transactio"
				"n with invalid object type, %lx\n",
				proc->pid, thread->pid, fp->type);
			return_error = BR_FAILED_REPLY;
			goto err_bad_object_type;
		}
	}
	if (reply) {
		BUG_ON(t->buffer->async_transaction != 0);
		binder_pop_transaction(target_thread, in_reply_to);
	} else if (!(t->flags & TF_ONE_WAY)) {
		// 如果是正在处理一个同步的进程间通信请求
		BUG_ON(t->buffer->async_transaction != 0);
		// 需要回复
		t->need_reply = 1;
		// 压入到源线程thread的事务堆栈transaction_stack中
		t->from_parent = thread->transaction_stack;
		thread->transaction_stack = t;
	} else {
		BUG_ON(target_node == NULL);
		BUG_ON(t->buffer->async_transaction != 1);
		// 检查是否正在处理异步事务
		if (target_node->has_async_transaction) {
			// 添加到async_todo队列中进行处理
			target_list = &target_node->async_todo;
			target_wait = NULL;
		} else
			target_node->has_async_transaction = 1;
	}
	// 将binder_transaction结构体t封装成BINDER_WORK_TRANSACTION的工作项添加到目标进程target_proc中
	t->work.type = BINDER_WORK_TRANSACTION;
	list_add_tail(&t->work.entry, target_list);
	// 将tcomplte封装成一个类型为BINDER_WORK_TRANSACTION_COMPLETE工作项添加到源线程thread的todo队列中
	tcomplete->type = BINDER_WORK_TRANSACTION_COMPLETE;
	list_add_tail(&tcomplete->entry, &thread->todo);
	if (target_wait)
		// 将target_proc或者target_thread唤醒，来处理这个重做向
		wake_up_interruptible(target_wait);
		// 执行到这里时，源线程thread,目标进程target_proc或者目标线程target_thread就会并发的去处理各自的todo队列的工作项了
	return;

err_get_unused_fd_failed:
err_fget_failed:
err_fd_not_allowed:
err_binder_get_ref_for_node_failed:
err_binder_get_ref_failed:
err_binder_new_node_failed:
err_bad_object_type:
err_bad_offset:
err_copy_data_failed:
	binder_transaction_buffer_release(target_proc, t->buffer, offp);
	t->buffer->transaction = NULL;
	binder_free_buf(target_proc, t->buffer);
err_binder_alloc_buf_failed:
	kfree(tcomplete);
	binder_stats.obj_deleted[BINDER_STAT_TRANSACTION_COMPLETE]++;
err_alloc_tcomplete_failed:
	kfree(t);
	binder_stats.obj_deleted[BINDER_STAT_TRANSACTION]++;
err_alloc_t_failed:
err_bad_call_stack:
err_empty_call_stack:
err_dead_binder:
err_invalid_target_handle:
err_no_context_mgr_node:
	if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
		printk(KERN_INFO "binder: %d:%d transaction failed %d, size"
				"%zd-%zd\n",
			   proc->pid, thread->pid, return_error,
			   tr->data_size, tr->offsets_size);

	{
		struct binder_transaction_log_entry *fe;
		fe = binder_transaction_log_add(&binder_transaction_log_failed);
		*fe = *e;
	}

	BUG_ON(thread->return_error != BR_OK);
	if (in_reply_to) {
		thread->return_error = BR_TRANSACTION_COMPLETE;
		binder_send_failed_reply(in_reply_to, return_error);
	} else
		thread->return_error = return_error;
}

static void
binder_transaction_buffer_release(struct binder_proc *proc, struct binder_buffer *buffer, size_t *failed_at)
{
	size_t *offp, *off_end;
	int debug_id = buffer->debug_id;

	if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
		printk(KERN_INFO "binder: %d buffer release %d, size %zd-%zd, failed at %p\n",
			   proc->pid, buffer->debug_id,
			   buffer->data_size, buffer->offsets_size, failed_at);

	if (buffer->target_node)
		binder_dec_node(buffer->target_node, 1, 0);

	offp = (size_t *)(buffer->data + ALIGN(buffer->data_size, sizeof(void *)));
	if (failed_at)
		off_end = failed_at;
	else
		off_end = (void *)offp + buffer->offsets_size;
	for (; offp < off_end; offp++) {
		struct flat_binder_object *fp;
		if (*offp > buffer->data_size - sizeof(*fp) ||
		    buffer->data_size < sizeof(*fp) ||
		    !IS_ALIGNED(*offp, sizeof(void *))) {
			printk(KERN_ERR "binder: transaction release %d bad"
					"offset %zd, size %zd\n", debug_id, *offp, buffer->data_size);
			continue;
		}
		fp = (struct flat_binder_object *)(buffer->data + *offp);
		switch (fp->type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct binder_node *node = binder_get_node(proc, fp->binder);
			if (node == NULL) {
				printk(KERN_ERR "binder: transaction release %d bad node %p\n", debug_id, fp->binder);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printk(KERN_INFO "        node %d u%p\n",
				       node->debug_id, node->ptr);
			binder_dec_node(node, fp->type == BINDER_TYPE_BINDER, 0);
		} break;
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct binder_ref *ref = binder_get_ref(proc, fp->handle);
			if (ref == NULL) {
				printk(KERN_ERR "binder: transaction release %d bad handle %ld\n", debug_id, fp->handle);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printk(KERN_INFO "        ref %d desc %d (node %d)\n",
				       ref->debug_id, ref->desc, ref->node->debug_id);
			binder_dec_ref(ref, fp->type == BINDER_TYPE_HANDLE);
		} break;

		case BINDER_TYPE_FD:
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
				printk(KERN_INFO "        fd %ld\n", fp->handle);
			if (failed_at)
				task_close_fd(proc, fp->handle);
			break;

		default:
			printk(KERN_ERR "binder: transaction release %d bad object type %lx\n", debug_id, fp->type);
			break;
		}
	}
}

// Binder引用对象为binder_ref
// 它在Binder驱动程序中创建，并且被用户空间中的Binder代理对象所引用
// 当Client进程引用了Server进程中的一个Binder本地对象时，Binder驱动程序就会在内部为它创建了一个Binder引用对象
// Binder引用对象运行在内核空间，引用了它的Binder代理对象运行在用户空间
// Client与Binder驱动需要约定一套规则来维护Binder引用对象的引用计数，避免它们在还被Binder代理对象引用的情况下被销毁
//
// 驱动会根据Client进程传进来的句柄值找到需要修改引用计数的Binder引用对象
// 句柄值是Binder驱动程序为Client进程创建的
// 用来关联用户空间的Binder代理对象和内核空间的Binder引用对象
//
// 当一个使用IO命令BINDER_WRITE_READ和Binder驱动交互时
// 传递给binder_write_read结构体的输入缓冲区长度大于0，那么会调用binder_thread_write来处理输入缓冲区的命令协议
// 传递给binder_write_read结构体的输出缓冲区长度大于0，那么会调用binder_thread_read来处理输出缓冲区的命令协议
int
binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
		    void __user *buffer, int size, signed long *consumed)
{
	uint32_t cmd;
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

	while (ptr < end && thread->return_error == BR_OK) {
		if (get_user(cmd, (uint32_t __user *)ptr))
			return -EFAULT;
		ptr += sizeof(uint32_t);
		if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.bc)) {
			binder_stats.bc[_IOC_NR(cmd)]++;
			proc->stats.bc[_IOC_NR(cmd)]++;
			thread->stats.bc[_IOC_NR(cmd)]++;
		}
		switch (cmd) {
		case BC_INCREFS:
		case BC_ACQUIRE:
		case BC_RELEASE:
		case BC_DECREFS: {
			uint32_t target;
			struct binder_ref *ref;
			const char *debug_string;

			// 获取句柄值，保存在target中
			if (get_user(target, (uint32_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(uint32_t);
			// 得到目标Binder引用对象ref
			// 判断句柄值是否为0
			if (target == 0 && binder_context_mgr_node &&
			    (cmd == BC_INCREFS || cmd == BC_ACQUIRE)) {
				// 是否存在一个引用了ServiceManager的实体对象
				ref = binder_get_ref_for_node(proc,
					       binder_context_mgr_node);
				if (ref->desc != target) {
					binder_user_error("binder: %d:"
						"%d tried to acquire "
						"reference to desc 0, "
						"got %d instead\n",
						proc->pid, thread->pid,
						ref->desc);
				}
			} else
				ref = binder_get_ref(proc, target);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d refcou"
					"nt change on invalid ref %d\n",
					proc->pid, thread->pid, target);
				break;
			}
			// 根据不同的协议来增加或者减少它的强引用计数或者弱引用计数
			switch (cmd) {
			case BC_INCREFS:
				debug_string = "IncRefs";
				binder_inc_ref(ref, 0, NULL);
				break;
			case BC_ACQUIRE:
				debug_string = "Acquire";
				binder_inc_ref(ref, 1, NULL);
				break;
			case BC_RELEASE:
				debug_string = "Release";
				binder_dec_ref(ref, 1);
				break;
			case BC_DECREFS:
			default:
				debug_string = "DecRefs";
				binder_dec_ref(ref, 0);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_USER_REFS)
				printk(KERN_INFO "binder: %d:%d %s ref %d desc %d s %d w %d for node %d\n",
				       proc->pid, thread->pid, debug_string, ref->debug_id, ref->desc, ref->strong, ref->weak, ref->node->debug_id);
			break;
		}
		case BC_INCREFS_DONE:
		case BC_ACQUIRE_DONE: {
			void __user *node_ptr;
			void *cookie;
			struct binder_node *node;

			if (get_user(node_ptr, (void * __user *)ptr))
				return -EFAULT;
			ptr += sizeof(void *);
			if (get_user(cookie, (void * __user *)ptr))
				return -EFAULT;
			ptr += sizeof(void *);
			node = binder_get_node(proc, node_ptr);
			if (node == NULL) {
				binder_user_error("binder: %d:%d "
					"%s u%p no match\n",
					proc->pid, thread->pid,
					cmd == BC_INCREFS_DONE ?
					"BC_INCREFS_DONE" :
					"BC_ACQUIRE_DONE",
					node_ptr);
				break;
			}
			if (cookie != node->cookie) {
				binder_user_error("binder: %d:%d %s u%p node %d"
					" cookie mismatch %p != %p\n",
					proc->pid, thread->pid,
					cmd == BC_INCREFS_DONE ?
					"BC_INCREFS_DONE" : "BC_ACQUIRE_DONE",
					node_ptr, node->debug_id,
					cookie, node->cookie);
				break;
			}
			if (cmd == BC_ACQUIRE_DONE) {
				if (node->pending_strong_ref == 0) {
					binder_user_error("binder: %d:%d "
						"BC_ACQUIRE_DONE node %d has "
						"no pending acquire request\n",
						proc->pid, thread->pid,
						node->debug_id);
					break;
				}
				node->pending_strong_ref = 0;
			} else {
				if (node->pending_weak_ref == 0) {
					binder_user_error("binder: %d:%d "
						"BC_INCREFS_DONE node %d has "
						"no pending increfs request\n",
						proc->pid, thread->pid,
						node->debug_id);
					break;
				}
				node->pending_weak_ref = 0;
			}
			binder_dec_node(node, cmd == BC_ACQUIRE_DONE, 0);
			if (binder_debug_mask & BINDER_DEBUG_USER_REFS)
				printk(KERN_INFO "binder: %d:%d %s node %d ls %d lw %d\n",
				       proc->pid, thread->pid, cmd == BC_INCREFS_DONE ? "BC_INCREFS_DONE" : "BC_ACQUIRE_DONE", node->debug_id, node->local_strong_refs, node->local_weak_refs);
			break;
		}
		case BC_ATTEMPT_ACQUIRE:
			printk(KERN_ERR "binder: BC_ATTEMPT_ACQUIRE not supported\n");
			return -EINVAL;
		case BC_ACQUIRE_RESULT:
			printk(KERN_ERR "binder: BC_ACQUIRE_RESULT not supported\n");
			return -EINVAL;

		case BC_FREE_BUFFER: {
			void __user *data_ptr;
			struct binder_buffer *buffer;

			if (get_user(data_ptr, (void * __user *)ptr))
				return -EFAULT;
			ptr += sizeof(void *);

			buffer = binder_buffer_lookup(proc, data_ptr);
			if (buffer == NULL) {
				binder_user_error("binder: %d:%d "
					"BC_FREE_BUFFER u%p no match\n",
					proc->pid, thread->pid, data_ptr);
				break;
			}
			if (!buffer->allow_user_free) {
				binder_user_error("binder: %d:%d "
					"BC_FREE_BUFFER u%p matched "
					"unreturned buffer\n",
					proc->pid, thread->pid, data_ptr);
				break;
			}
			if (binder_debug_mask & BINDER_DEBUG_FREE_BUFFER)
				printk(KERN_INFO "binder: %d:%d BC_FREE_BUFFER u%p found buffer %d for %s transaction\n",
				       proc->pid, thread->pid, data_ptr, buffer->debug_id,
				       buffer->transaction ? "active" : "finished");

			if (buffer->transaction) {
				buffer->transaction->buffer = NULL;
				buffer->transaction = NULL;
			}
			if (buffer->async_transaction && buffer->target_node) {
				BUG_ON(!buffer->target_node->has_async_transaction);
				if (list_empty(&buffer->target_node->async_todo))
					buffer->target_node->has_async_transaction = 0;
				else
					list_move_tail(buffer->target_node->async_todo.next, &thread->todo);
			}
			binder_transaction_buffer_release(proc, buffer, NULL);
			binder_free_buf(proc, buffer);
			break;
		}

		case BC_TRANSACTION:
		case BC_REPLY: {
			struct binder_transaction_data tr;

			if (copy_from_user(&tr, ptr, sizeof(tr)))
				return -EFAULT;
			ptr += sizeof(tr);
			// 处理协议
			binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
			break;
		}

		case BC_REGISTER_LOOPER:
			if (binder_debug_mask & BINDER_DEBUG_THREADS)
				printk(KERN_INFO "binder: %d:%d BC_REGISTER_LOOPER\n",
				       proc->pid, thread->pid);
			if (thread->looper & BINDER_LOOPER_STATE_ENTERED) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR:"
					" BC_REGISTER_LOOPER called "
					"after BC_ENTER_LOOPER\n",
					proc->pid, thread->pid);
			} else if (proc->requested_threads == 0) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR:"
					" BC_REGISTER_LOOPER called "
					"without request\n",
					proc->pid, thread->pid);
			} else {
				proc->requested_threads--;
				proc->requested_threads_started++;
			}
			thread->looper |= BINDER_LOOPER_STATE_REGISTERED;
			break;
		case BC_ENTER_LOOPER:
			if (binder_debug_mask & BINDER_DEBUG_THREADS)
				printk(KERN_INFO "binder: %d:%d BC_ENTER_LOOPER\n",
				       proc->pid, thread->pid);
			if (thread->looper & BINDER_LOOPER_STATE_REGISTERED) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR:"
					" BC_ENTER_LOOPER called after "
					"BC_REGISTER_LOOPER\n",
					proc->pid, thread->pid);
			}
			// 设置状态
			thread->looper |= BINDER_LOOPER_STATE_ENTERED;
			break;
		case BC_EXIT_LOOPER:
			if (binder_debug_mask & BINDER_DEBUG_THREADS)
				printk(KERN_INFO "binder: %d:%d BC_EXIT_LOOPER\n",
				       proc->pid, thread->pid);
			thread->looper |= BINDER_LOOPER_STATE_EXITED;
			break;

		case BC_REQUEST_DEATH_NOTIFICATION:
		case BC_CLEAR_DEATH_NOTIFICATION: {
			uint32_t target;
			void __user *cookie;
			struct binder_ref *ref;
			struct binder_ref_death *death;

			// 获取对象的句柄值和地址值并保存在target和cookie变量中
			if (get_user(target, (uint32_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(uint32_t);
			if (get_user(cookie, (void __user * __user *)ptr))
				return -EFAULT;
			ptr += sizeof(void *);
			// 根据target获取到Binder引用对象ref
			ref = binder_get_ref(proc, target);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d %s "
					"invalid ref %d\n",
					proc->pid, thread->pid,
					cmd == BC_REQUEST_DEATH_NOTIFICATION ?
					"BC_REQUEST_DEATH_NOTIFICATION" :
					"BC_CLEAR_DEATH_NOTIFICATION",
					target);
				break;
			}

			if (binder_debug_mask & BINDER_DEBUG_DEATH_NOTIFICATION)
				printk(KERN_INFO "binder: %d:%d %s %p ref %d desc %d s %d w %d for node %d\n",
				       proc->pid, thread->pid,
				       cmd == BC_REQUEST_DEATH_NOTIFICATION ?
				       "BC_REQUEST_DEATH_NOTIFICATION" :
				       "BC_CLEAR_DEATH_NOTIFICATION",
				       cookie, ref->debug_id, ref->desc,
				       ref->strong, ref->weak, ref->node->debug_id);

			if (cmd == BC_REQUEST_DEATH_NOTIFICATION) {
				// 检查是否已经注册过死亡通知
				// 驱动不会重复的注册死亡接收通知
				if (ref->death) {
					binder_user_error("binder: %d:%"
						"d BC_REQUEST_DEATH_NOTI"
						"FICATION death notific"
						"ation already set\n",
						proc->pid, thread->pid);
					break;
				}
				// 第一次注册的话，会创建出一个binder_ref_death的结构体
				death = kzalloc(sizeof(*death), GFP_KERNEL);
				if (death == NULL) {
					thread->return_error = BR_ERROR;
					if (binder_debug_mask & BINDER_DEBUG_FAILED_TRANSACTION)
						printk(KERN_INFO "binder: %d:%d "
							"BC_REQUEST_DEATH_NOTIFICATION failed\n",
							proc->pid, thread->pid);
					break;
				}
				binder_stats.obj_created[BINDER_STAT_DEATH]++;
				INIT_LIST_HEAD(&death->work.entry);
				// 将cookie保存在它的成员变量cookie中
				death->cookie = cookie;
				ref->death = death;
				// 如果正在注册的Binder引用对象所引用的Binder本地对象已经死亡了
				// 这时候驱动会马上向Client发送一个死亡接收通知
				if (ref->node->proc == NULL) {
					ref->death->work.type = BINDER_WORK_DEAD_BINDER;
					// 将一个类型为BINDER_WORK_DEAD_BINDER的工作项添加到当前或者当前线程所在的Client进程的todo队列中
					if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
						list_add_tail(&ref->death->work.entry, &thread->todo);
					} else {
						list_add_tail(&ref->death->work.entry, &proc->todo);
						wake_up_interruptible(&proc->wait);
					}
				}
			} else {
				if (ref->death == NULL) {
					binder_user_error("binder: %d:%"
						"d BC_CLEAR_DEATH_NOTIFI"
						"CATION death notificat"
						"ion not active\n",
						proc->pid, thread->pid);
					break;
				}
				death = ref->death;
				if (death->cookie != cookie) {
					binder_user_error("binder: %d:%"
						"d BC_CLEAR_DEATH_NOTIFI"
						"CATION death notificat"
						"ion cookie mismatch "
						"%p != %p\n",
						proc->pid, thread->pid,
						death->cookie, cookie);
					break;
				}
				// 清理用来描述死亡接收者的binder_ref_death结构体
				ref->death = NULL;
				if (list_empty(&death->work.entry)) {
					death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
					if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
						// 向当前线程或者线程所属的Client进程的todo队列中添加一个类型为BINDER_WORK_CLEAR_DEATH_NOTIFICATION的工作项
						// 然后发送给Client进程
						list_add_tail(&death->work.entry, &thread->todo);
					} else {
						list_add_tail(&death->work.entry, &proc->todo);
						wake_up_interruptible(&proc->wait);
					}
				} else {
					BUG_ON(death->work.type != BINDER_WORK_DEAD_BINDER);
					death->work.type = BINDER_WORK_DEAD_BINDER_AND_CLEAR;
				}
			}
		} break;
		case BC_DEAD_BINDER_DONE: {
			struct binder_work *w;
			void __user *cookie;
			struct binder_ref_death *death = NULL;
			if (get_user(cookie, (void __user * __user *)ptr))
				return -EFAULT;

			ptr += sizeof(void *);
			list_for_each_entry(w, &proc->delivered_death, entry) {
				struct binder_ref_death *tmp_death = container_of(w, struct binder_ref_death, work);
				if (tmp_death->cookie == cookie) {
					death = tmp_death;
					break;
				}
			}
			if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
				printk(KERN_INFO "binder: %d:%d BC_DEAD_BINDER_DONE %p found %p\n",
				       proc->pid, thread->pid, cookie, death);
			if (death == NULL) {
				binder_user_error("binder: %d:%d BC_DEAD"
					"_BINDER_DONE %p not found\n",
					proc->pid, thread->pid, cookie);
				break;
			}

			list_del_init(&death->work.entry);
			if (death->work.type == BINDER_WORK_DEAD_BINDER_AND_CLEAR) {
				death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
				if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
					list_add_tail(&death->work.entry, &thread->todo);
				} else {
					list_add_tail(&death->work.entry, &proc->todo);
					wake_up_interruptible(&proc->wait);
				}
			}
		} break;

		default:
			printk(KERN_ERR "binder: %d:%d unknown command %d\n", proc->pid, thread->pid, cmd);
			return -EINVAL;
		}
		*consumed = ptr - buffer;
	}
	return 0;
}

void
binder_stat_br(struct binder_proc *proc, struct binder_thread *thread, uint32_t cmd)
{
	if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.br)) {
		binder_stats.br[_IOC_NR(cmd)]++;
		proc->stats.br[_IOC_NR(cmd)]++;
		thread->stats.br[_IOC_NR(cmd)]++;
	}
}

// 进程是否有未处理的工作项
static int
binder_has_proc_work(struct binder_proc *proc, struct binder_thread *thread)
{
	return !list_empty(&proc->todo) || (thread->looper & BINDER_LOOPER_STATE_NEED_RETURN);
}

// 线程是否有未处理端的工作项
static int
binder_has_thread_work(struct binder_thread *thread)
{
	return !list_empty(&thread->todo) || thread->return_error != BR_OK ||
		(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN);
}

// service manager睡眠在驱动的binder_thread_read中，等待其它进程service组件或者client组件发送进程间通信请求
//
// 当驱动将BINDER_WORK_TRANSACTION工作项添加到Service Manager进程的todo队列后，service manager会被唤醒，继续执行binder_thread_read
static int
binder_thread_read(struct binder_proc *proc, struct binder_thread *thread,
	void  __user *buffer, int size, signed long *consumed, int non_block)
{
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

	int ret = 0;
	int wait_for_proc_work;

	if (*consumed == 0) {
		if (put_user(BR_NOOP, (uint32_t __user *)ptr))
			return -EFAULT;
		ptr += sizeof(uint32_t);
	}

retry:
	// 如果一个事务的堆栈transaction_stack不等于NULL，就表示它正在等待其他进程完成另外一个事务
	// 只有在transaction_stack为空并且todo队列为空时，才可以去处理其所属进程的todo队列待处理工作项
	// 否则，它就要处理其事务堆栈中的事务或者todo队列中的待处理工作项
	wait_for_proc_work = thread->transaction_stack == NULL && list_empty(&thread->todo);

	if (thread->return_error != BR_OK && ptr < end) {
		if (thread->return_error2 != BR_OK) {
			if (put_user(thread->return_error2, (uint32_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(uint32_t);
			if (ptr == end)
				goto done;
			thread->return_error2 = BR_OK;
		}
		if (put_user(thread->return_error, (uint32_t __user *)ptr))
			return -EFAULT;
		ptr += sizeof(uint32_t);
		thread->return_error = BR_OK;
		goto done;
	}


	// 首先将当前线程状态设置为BINDER_LOOPER_STATE_WATING
	// 表示该线程处于空闲状态
	thread->looper |= BINDER_LOOPER_STATE_WAITING;
	if (wait_for_proc_work)
		// 空闲线程加1
		proc->ready_threads++;
	mutex_unlock(&binder_lock);
	if (wait_for_proc_work) {
		if (!(thread->looper & (BINDER_LOOPER_STATE_REGISTERED |
					BINDER_LOOPER_STATE_ENTERED))) {
			binder_user_error("binder: %d:%d ERROR: Thread waiting "
				"for process work before calling BC_REGISTER_"
				"LOOPER or BC_ENTER_LOOPER (state %x)\n",
				proc->pid, thread->pid, thread->looper);
			wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
		}
		// 设置当前线程优先级为进程优先级
		binder_set_nice(proc->default_priority);
		if (non_block) {
			// 当前线程不可以在驱动中睡眠
			if (!binder_has_proc_work(proc, thread))
				ret = -EAGAIN;
		} else
			// 否则，睡眠等待直到所属的进程有新的未处理工作项为止
			ret = wait_event_interruptible_exclusive(proc->wait, binder_has_proc_work(proc, thread));
	} else {
		// 是否以非阻塞模式打开设备文件/dev/binder
		if (non_block) {
			if (!binder_has_thread_work(thread))
				ret = -EAGAIN;
		} else
			ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
	}
	mutex_lock(&binder_lock);
	// 根据状态为来减少空闲线程
	if (wait_for_proc_work)
		proc->ready_threads--;
	// 如果驱动发现当前线程有新的工作项时，就会将它的状态为清空
	thread->looper &= ~BINDER_LOOPER_STATE_WAITING;

	if (ret)
		return ret;

	// 当驱动和目标进程/线程通信时
	// 会把一个工作项加入到它的todo队列中
	// 目标进程/进程会不断的调用驱动中的函数binder_thread_read来检查它的todo队列中有没有新的工作项
	// 如果有，目标进程/线程就会把它取出来，并且返回到用户空间去处理
	while (1) {
		uint32_t cmd;
		struct binder_transaction_data tr;
		struct binder_work *w;
		struct binder_transaction *t = NULL;

		// 检查目标进程/线程中的todo队列，并且将里面的待处理工作项保存在w中
		if (!list_empty(&thread->todo))
			w = list_first_entry(&thread->todo, struct binder_work, entry);
		else if (!list_empty(&proc->todo) && wait_for_proc_work)
			w = list_first_entry(&proc->todo, struct binder_work, entry);
		else {
			if (ptr - buffer == 4 && !(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN)) /* no data added */
				goto retry;
			break;
		}

		if (end - ptr < sizeof(tr) + 4)
			break;

		switch (w->type) {
		case BINDER_WORK_TRANSACTION: {
			// 转换成binder_transaction结构体
			t = container_of(w, struct binder_transaction, work);
		} break;
		case BINDER_WORK_TRANSACTION_COMPLETE: {
			cmd = BR_TRANSACTION_COMPLETE;
			// 将一个BR_TRANSACTION_COMPLETE返回协议写入到用户空间提供的缓冲区中
			// 向相应的进程发送一个BR_TRANSACTION_COMPLETE协议
			if (put_user(cmd, (uint32_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(uint32_t);

			binder_stat_br(proc, thread, cmd);
			if (binder_debug_mask & BINDER_DEBUG_TRANSACTION_COMPLETE)
				printk(KERN_INFO "binder: %d:%d BR_TRANSACTION_COMPLETE\n",
				       proc->pid, thread->pid);

			list_del(&w->entry);
			kfree(w);
			binder_stats.obj_deleted[BINDER_STAT_TRANSACTION_COMPLETE]++;
		} break;
		case BINDER_WORK_NODE: {
			struct binder_node *node = container_of(w, struct binder_node, work);
			uint32_t cmd = BR_NOOP;
			const char *cmd_name;
			// 检查该Binder实体对象是否有强引用和弱引用计数
			int strong = node->internal_strong_refs || node->local_strong_refs;
			// 是否有弱引用计数
			int weak = !hlist_empty(&node->refs) || node->local_weak_refs || strong;
			if (weak && !node->has_weak_ref) {
				// Binder实体对象已经引用了一个Binder本地对象
				// 但是并没有增加它的弱引用计数
				// 使用BC_INCREFS来增加对应的Binder本地对象的弱引用计数
				cmd = BR_INCREFS;
				cmd_name = "BR_INCREFS";
				node->has_weak_ref = 1;
				node->pending_weak_ref = 1;
				node->local_weak_refs++;
			} else if (strong && !node->has_strong_ref) {
				// Binder实体对象已经引用了一个Binder本地对象
				// 但是并没有增加它的强引用计数
				// 使用BC_ACQUIRE协议来请求增加对应的Binder本地对象的强引用计数
				cmd = BR_ACQUIRE;
				cmd_name = "BR_ACQUIRE";
				node->has_strong_ref = 1;
				node->pending_strong_ref = 1;
				node->local_strong_refs++;
			} else if (!strong && node->has_strong_ref) {
				// Binder实体对象已经不再引用一个Binder本地对象
				// 但是没有减少它的强引用计数
				// 使用BR_RELEASE协议来请求减少对应的Binder本地对象的强引用计数
				cmd = BR_RELEASE;
				cmd_name = "BR_RELEASE";
				node->has_strong_ref = 0;
			} else if (!weak && node->has_weak_ref) {
				// Binder实体对象已经不再引用Binder本地对象
				// 但是没有减少它的弱引用计数
				// 使用BR_DECREFS协议来请求减少对应的Binder本地对象的弱引用计数
				cmd = BR_DECREFS;
				cmd_name = "BR_DECREFS";
				node->has_weak_ref = 0;
			}
			if (cmd != BR_NOOP) {
				// 将前面准备好的协议以及协议内容写入到由Server进程所提供的一个用户空间缓冲区
				// 然后返回到Server进程的用户空间
				// Server进程通过Binder库提供的IPCThreadState接口来处理Binder驱动程序所发送的协议
				if (put_user(cmd, (uint32_t __user *)ptr))
					return -EFAULT;
				ptr += sizeof(uint32_t);
				if (put_user(node->ptr, (void * __user *)ptr))
					return -EFAULT;
				ptr += sizeof(void *);
				if (put_user(node->cookie, (void * __user *)ptr))
					return -EFAULT;
				ptr += sizeof(void *);

				binder_stat_br(proc, thread, cmd);
				if (binder_debug_mask & BINDER_DEBUG_USER_REFS)
					printk(KERN_INFO "binder: %d:%d %s %d u%p c%p\n",
					       proc->pid, thread->pid, cmd_name, node->debug_id, node->ptr, node->cookie);
			} else {
				list_del_init(&w->entry);
				if (!weak && !strong) {
					if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
						printk(KERN_INFO "binder: %d:%d node %d u%p c%p deleted\n",
						       proc->pid, thread->pid, node->debug_id, node->ptr, node->cookie);
					rb_erase(&node->rb_node, &proc->nodes);
					kfree(node);
					binder_stats.obj_deleted[BINDER_STAT_NODE]++;
				} else {
					if (binder_debug_mask & BINDER_DEBUG_INTERNAL_REFS)
						printk(KERN_INFO "binder: %d:%d node %d u%p c%p state unchanged\n",
						       proc->pid, thread->pid, node->debug_id, node->ptr, node->cookie);
				}
			}
		} break;
		case BINDER_WORK_DEAD_BINDER:
		case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
		case BINDER_WORK_CLEAR_DEATH_NOTIFICATION: {
			// Binder线程在空闲时，会睡眠在Binder驱动程序的函数binder_thread_read中，因此，当它们被唤醒时
			// 就会执行函数binder_thread_read，并且检查自己以及宿主进程的todo队列，看看有没有工作项需要处理
			//
			// 获得一个对应的binder_ref_death结构体
			struct binder_ref_death *death = container_of(w, struct binder_ref_death, work);
			uint32_t cmd;
			if (w->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION)
				cmd = BR_CLEAR_DEATH_NOTIFICATION_DONE;
			else
				cmd = BR_DEAD_BINDER;
			// 将协议代码和binder_ref_death结构体成员变量写入到Client进程提供的一个用户空间缓冲区中
			if (put_user(cmd, (uint32_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(uint32_t);
			// 通知Client进程，哪一个Binder代理对象已经死亡
			if (put_user(death->cookie, (void * __user *)ptr))
				return -EFAULT;
			ptr += sizeof(void *);
			if (binder_debug_mask & BINDER_DEBUG_DEATH_NOTIFICATION)
				printk(KERN_INFO "binder: %d:%d %s %p\n",
				       proc->pid, thread->pid,
				       cmd == BR_DEAD_BINDER ?
				       "BR_DEAD_BINDER" :
				       "BR_CLEAR_DEATH_NOTIFICATION_DONE",
				       death->cookie);

			if (w->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION) {
				list_del(&w->entry);
				kfree(death);
				binder_stats.obj_deleted[BINDER_STAT_DEATH]++;
			} else
				// 将正在处理的工作项保存在Client进程的一个delivered_death队列中
				// 当处理完成一个死亡通知之后，它就会使用协议BC_DEAD_BINDER_DONE来通知Binder驱动程序
				// 如果一个进程的delivered_death队列不为空
				// 那么就说明Binder驱动程序正在向他发送死亡接受通知
				list_move(&w->entry, &proc->delivered_death);
			if (cmd == BR_DEAD_BINDER)
				goto done; /* DEAD_BINDER notifications can cause transactions */
		} break;
		}

		if (!t)
			continue;

		BUG_ON(t->buffer == NULL);
		if (t->buffer->target_node) {
			struct binder_node *target_node = t->buffer->target_node;
			tr.target.ptr = target_node->ptr;
			tr.cookie =  target_node->cookie;
			t->saved_priority = task_nice(current);
			if (t->priority < target_node->min_priority &&
			    !(t->flags & TF_ONE_WAY))
				binder_set_nice(t->priority);
			else if (!(t->flags & TF_ONE_WAY) ||
				 t->saved_priority > target_node->min_priority)
				binder_set_nice(target_node->min_priority);
			cmd = BR_TRANSACTION;
		} else {
			tr.target.ptr = NULL;
			tr.cookie = NULL;
			cmd = BR_REPLY;
		}
		tr.code = t->code;
		tr.flags = t->flags;
		tr.sender_euid = t->sender_euid;

		if (t->from) {
			struct task_struct *sender = t->from->proc->tsk;
			tr.sender_pid = task_tgid_nr_ns(sender, current->nsproxy->pid_ns);
		} else {
			tr.sender_pid = 0;
		}

		tr.data_size = t->buffer->data_size;
		tr.offsets_size = t->buffer->offsets_size;
		tr.data.ptr.buffer = (void *)t->buffer->data + proc->user_buffer_offset;
		tr.data.ptr.offsets = tr.data.ptr.buffer + ALIGN(t->buffer->data_size, sizeof(void *));

		if (put_user(cmd, (uint32_t __user *)ptr))
			return -EFAULT;
		ptr += sizeof(uint32_t);
		if (copy_to_user(ptr, &tr, sizeof(tr)))
			return -EFAULT;
		ptr += sizeof(tr);

		binder_stat_br(proc, thread, cmd);
		if (binder_debug_mask & BINDER_DEBUG_TRANSACTION)
			printk(KERN_INFO "binder: %d:%d %s %d %d:%d, cmd %d"
				"size %zd-%zd ptr %p-%p\n",
			       proc->pid, thread->pid,
			       (cmd == BR_TRANSACTION) ? "BR_TRANSACTION" : "BR_REPLY",
			       t->debug_id, t->from ? t->from->proc->pid : 0,
			       t->from ? t->from->pid : 0, cmd,
			       t->buffer->data_size, t->buffer->offsets_size,
			       tr.data.ptr.buffer, tr.data.ptr.offsets);

		list_del(&t->work.entry);
		t->buffer->allow_user_free = 1;
		if (cmd == BR_TRANSACTION && !(t->flags & TF_ONE_WAY)) {
			t->to_parent = thread->transaction_stack;
			t->to_thread = thread;
			thread->transaction_stack = t;
		} else {
			t->buffer->transaction = NULL;
			kfree(t);
			binder_stats.obj_deleted[BINDER_STAT_TRANSACTION]++;
		}
		break;
	}

// 在处理完成之后，返回到函数binder_ioctl之前
// 还会检查是否需要请求当前线程所属的进程proc增加一个新的Binder线程来处理进程间通信请求
done:

	*consumed = ptr - buffer;
	// 1. 空闲进程为0
	// 2. 驱动当前没有请求进程proc增加一个新的Binder线程
	// 3. 驱动请求进程proc增加Binder线程数小于预设的最大数目
	// 4. 当前线程是一个已经注册了的Binder线程
	if (proc->requested_threads + proc->ready_threads == 0 &&
	    proc->requested_threads_started < proc->max_threads &&
	    (thread->looper & (BINDER_LOOPER_STATE_REGISTERED |
	     BINDER_LOOPER_STATE_ENTERED)) /* the user-space code fails to */
	     /*spawn a new thread if we leave this out */) {
		proc->requested_threads++;
		if (binder_debug_mask & BINDER_DEBUG_THREADS)
			printk(KERN_INFO "binder: %d:%d BR_SPAWN_LOOPER\n",
			       proc->pid, thread->pid);
		// 返回BR_SPAWN_LOOPER到用户空间缓冲区
		// 以便可以创建一个新的线程加入到Binder线程池中
		if (put_user(BR_SPAWN_LOOPER, (uint32_t __user *)buffer))
			return -EFAULT;
	}
	return 0;
}

static void binder_release_work(struct list_head *list)
{
	struct binder_work *w;
	while (!list_empty(list)) {
		w = list_first_entry(list, struct binder_work, entry);
		list_del_init(&w->entry);
		switch (w->type) {
		case BINDER_WORK_TRANSACTION: {
			struct binder_transaction *t = container_of(w, struct binder_transaction, work);
			if (t->buffer->target_node && !(t->flags & TF_ONE_WAY))
				binder_send_failed_reply(t, BR_DEAD_REPLY);
		} break;
		case BINDER_WORK_TRANSACTION_COMPLETE: {
			kfree(w);
			binder_stats.obj_deleted[BINDER_STAT_TRANSACTION_COMPLETE]++;
		} break;
		default:
			break;
		}
	}

}

static struct binder_thread *binder_get_thread(struct binder_proc *proc)
{
	struct binder_thread *thread = NULL;
	struct rb_node *parent = NULL;
	// threads所描述的红黑树是以线程的PID为关键字来组织的
	struct rb_node **p = &proc->threads.rb_node;

	// 检查相应的binder_thread是否存在
	while (*p) {
		parent = *p;
		thread = rb_entry(parent, struct binder_thread, rb_node);

		if (current->pid < thread->pid)
			p = &(*p)->rb_left;
		else if (current->pid > thread->pid)
			p = &(*p)->rb_right;
		else
			break;
	}
	// 没有找到线程，则创建为当前线程创建一个binder_thread结构体
	if (*p == NULL) {
		thread = kzalloc(sizeof(*thread), GFP_KERNEL);
		if (thread == NULL)
			return NULL;
		binder_stats.obj_created[BINDER_STAT_THREAD]++;
		thread->proc = proc;
		thread->pid = current->pid;
		init_waitqueue_head(&thread->wait);
		INIT_LIST_HEAD(&thread->todo);
		rb_link_node(&thread->rb_node, parent, p);
		rb_insert_color(&thread->rb_node, &proc->threads);
		// 设置状态
		// 表示完成当前操作之后，需要马上返回到用户空间，而不可以去处理进程间的通信请求
		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		thread->return_error = BR_OK;
		thread->return_error2 = BR_OK;
	}
	return thread;
}

static int binder_free_thread(struct binder_proc *proc, struct binder_thread *thread)
{
	struct binder_transaction *t;
	struct binder_transaction *send_reply = NULL;
	int active_transactions = 0;

	rb_erase(&thread->rb_node, &proc->threads);
	t = thread->transaction_stack;
	if (t && t->to_thread == thread)
		send_reply = t;
	while (t) {
		active_transactions++;
		if (binder_debug_mask & BINDER_DEBUG_DEAD_TRANSACTION)
			printk(KERN_INFO "binder: release %d:%d transaction %d %s, still active\n",
			       proc->pid, thread->pid, t->debug_id, (t->to_thread == thread) ? "in" : "out");
		if (t->to_thread == thread) {
			t->to_proc = NULL;
			t->to_thread = NULL;
			if (t->buffer) {
				t->buffer->transaction = NULL;
				t->buffer = NULL;
			}
			t = t->to_parent;
		} else if (t->from == thread) {
			t->from = NULL;
			t = t->from_parent;
		} else
			BUG();
	}
	if (send_reply)
		binder_send_failed_reply(send_reply, BR_DEAD_REPLY);
	binder_release_work(&thread->todo);
	kfree(thread);
	binder_stats.obj_deleted[BINDER_STAT_THREAD]++;
	return active_transactions;
}

static unsigned int binder_poll(struct file *filp, struct poll_table_struct *wait)
{
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread = NULL;
	int wait_for_proc_work;

	mutex_lock(&binder_lock);
	thread = binder_get_thread(proc);

	wait_for_proc_work = thread->transaction_stack == NULL &&
		list_empty(&thread->todo) && thread->return_error == BR_OK;
	mutex_unlock(&binder_lock);

	if (wait_for_proc_work) {
		if (binder_has_proc_work(proc, thread))
			return POLLIN;
		poll_wait(filp, &proc->wait, wait);
		if (binder_has_proc_work(proc, thread))
			return POLLIN;
	} else {
		if (binder_has_thread_work(thread))
			return POLLIN;
		poll_wait(filp, &thread->wait, wait);
		if (binder_has_thread_work(thread))
			return POLLIN;
	}
	return 0;
}

// 最终使用这个函数来处理IO控制命令
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret;
	// 先获得为service manager创建的binder_proc结构体
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread;
	unsigned int size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;

	/*printk(KERN_INFO "binder_ioctl: %d:%d %x %lx\n", proc->pid, current->pid, cmd, arg);*/

	ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
	if (ret)
		return ret;

	mutex_lock(&binder_lock);
	// 获取为service manager创建的binder_thread结构体
	thread = binder_get_thread(proc);
	if (thread == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	switch (cmd) {
	case BINDER_WRITE_READ: {
		struct binder_write_read bwr;
		if (size != sizeof(struct binder_write_read)) {
			ret = -EINVAL;
			goto err;
		}
		// 从用户空间拷贝出binder_write_read结构体
		if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
			ret = -EFAULT;
			goto err;
		}
		if (binder_debug_mask & BINDER_DEBUG_READ_WRITE)
			printk(KERN_INFO "binder: %d:%d write %ld at %08lx, read %ld at %08lx\n",
			       proc->pid, thread->pid, bwr.write_size, bwr.write_buffer, bwr.read_size, bwr.read_buffer);
		if (bwr.write_size > 0) {
			ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
			if (ret < 0) {
				bwr.read_consumed = 0;
				if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
					ret = -EFAULT;
				goto err;
			}
		}
		if (bwr.read_size > 0) {
			// 处理完成，返回用户空间
			ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
			if (!list_empty(&proc->todo))
				wake_up_interruptible(&proc->wait);
			if (ret < 0) {
				if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
					ret = -EFAULT;
				goto err;
			}
		}
		if (binder_debug_mask & BINDER_DEBUG_READ_WRITE)
			printk(KERN_INFO "binder: %d:%d wrote %ld of %ld, read return %ld of %ld\n",
			       proc->pid, thread->pid, bwr.write_consumed, bwr.write_size, bwr.read_consumed, bwr.read_size);
		if (copy_to_user(ubuf, &bwr, sizeof(bwr))) {
			ret = -EFAULT;
			goto err;
		}
		break;
	}
	case BINDER_SET_MAX_THREADS:
		if (copy_from_user(&proc->max_threads, ubuf, sizeof(proc->max_threads))) {
			ret = -EINVAL;
			goto err;
		}
		break;
	case BINDER_SET_CONTEXT_MGR:
		// binder_context_mgr_node用来描述与Binder进程间通信机制的上下文管理者相对应的一个Binder实体对象
		// 如果不为空，说明前面已经有组件将自己注册为Binder进程间通信机制的上下文管理者了
		if (binder_context_mgr_node != NULL) {
			printk(KERN_ERR "binder: BINDER_SET_CONTEXT_MGR already set\n");
			ret = -EBUSY;
			goto err;
		}
		// binder_context_mgr_uid用来描述注册了Binder进程间通信机制的上下文管理者的进程的有效用户ID
		// 如果不为-1，则说明已经存在上下文管理者
		// 需要检查当前进程的有效用户ID是否等于全局变量的binder_context_mgr_uid
		//
		// Binder驱动允许同一个进程重复使用IO控制命令BINDER_SET_CONTEXT_MGR
		// 原因是一次调用可能没有成功将注册
		if (binder_context_mgr_uid != -1) {
			if (binder_context_mgr_uid != current->cred->euid) {
				printk(KERN_ERR "binder: BINDER_SET_"
				       "CONTEXT_MGR bad uid %d != %d\n",
				       current->cred->euid,
				       binder_context_mgr_uid);
				ret = -EPERM;
				goto err;
			}
		} else
			binder_context_mgr_uid = current->cred->euid;
		// 为ServiceManager创建一个Binder实体对象
		binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
		if (binder_context_mgr_node == NULL) {
			ret = -ENOMEM;
			goto err;
		}
		binder_context_mgr_node->local_weak_refs++;
		binder_context_mgr_node->local_strong_refs++;
		binder_context_mgr_node->has_strong_ref = 1;
		binder_context_mgr_node->has_weak_ref = 1;
		break;
	case BINDER_THREAD_EXIT:
		if (binder_debug_mask & BINDER_DEBUG_THREADS)
			printk(KERN_INFO "binder: %d:%d exit\n",
			       proc->pid, thread->pid);
		binder_free_thread(proc, thread);
		thread = NULL;
		break;
	case BINDER_VERSION:
		if (size != sizeof(struct binder_version)) {
			ret = -EINVAL;
			goto err;
		}
		if (put_user(BINDER_CURRENT_PROTOCOL_VERSION, &((struct binder_version *)ubuf)->protocol_version)) {
			ret = -EINVAL;
			goto err;
		}
		break;
	default:
		ret = -EINVAL;
		goto err;
	}
	ret = 0;
err:
	if (thread)
		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
	mutex_unlock(&binder_lock);
	wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
	if (ret && ret != -ERESTARTSYS)
		printk(KERN_INFO "binder: %d:%d ioctl %x %lx returned %d\n", proc->pid, current->pid, cmd, arg, ret);
	return ret;
}

static void binder_vma_open(struct vm_area_struct *vma)
{
	struct binder_proc *proc = vma->vm_private_data;
	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO
			"binder: %d open vm area %lx-%lx (%ld K) vma %lx pagep %lx\n",
			proc->pid, vma->vm_start, vma->vm_end,
			(vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
			(unsigned long)pgprot_val(vma->vm_page_prot));
	dump_stack();
}

static void binder_vma_close(struct vm_area_struct *vma)
{
	struct binder_proc *proc = vma->vm_private_data;
	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO
			"binder: %d close vm area %lx-%lx (%ld K) vma %lx pagep %lx\n",
			proc->pid, vma->vm_start, vma->vm_end,
			(vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
			(unsigned long)pgprot_val(vma->vm_page_prot));
	proc->vma = NULL;
	binder_defer_work(proc, BINDER_DEFERRED_PUT_FILES);
}

static struct vm_operations_struct binder_vm_ops = {
	.open = binder_vma_open,
	.close = binder_vma_close,
};

// 打开设备文件/dev/binder之后，还需要调用函数mmap把设备文件映射到进程的地址空间
// 然后才可以使用Binder进程间通信机制
// 设备文件对应的是一个虚拟设备，将它映射到进程的地址空间的目的不是对它的内容感兴趣
// 而是为了为进程分配内核缓冲区，以便他可以用来传输进程间的通信数据
//
// filp: 指向一个打开的文件结构体，它的成员变量private_data指向一个进程结构体binder_proc
// 它是在Binder驱动的binder_open中创建的
static int binder_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret;
	// 用来描述一段虚拟地址空间
	// 在Linux内核中，一个进程可以占用的虚拟地址空间是4G
	// 其中0-3G是用户地址空间，3G-4G是内核地址空间
	// 为了区分进程的用户地址空间和内核地址空间
	// Linux内核分别使用结构体vm_area_struct和vm_struct来描述它们
	// 结构体vm_struct所描述的内核地址空间范围只有(3G+896M+8M)-4G
	// 中间空出来的3G-(3G+896M+8M)是用来做特殊用途的
	// 其中，3G-(3G+896M)的896M空间是用来映射物理内存的前896M的
	// 它们之间有简单的线性对应关系
	// 而(3G+896M)-(3G+896M+8M)的8M空间是一个安全保护区，是用来检测非法指针的，所有指向这8M空间的指针都是非法的
	struct vm_struct *area;
	// 将参数filp的成员变量private_data转换为一个binder_proc结构体指针，保存在proc变量中
	struct binder_proc *proc = filp->private_data;
	const char *failure_string;
	struct binder_buffer *buffer;

	// 参数的成员变量vm_start和vm_end指定了要映射的用户空间地址范围
	// 判断是否超过了4M
	// 如果是,那么就将它截断为4M
	// Binder驱动最多为进程分配4M的内核缓冲区来传输数据
	if ((vma->vm_end - vma->vm_start) > SZ_4M)
		vma->vm_end = vma->vm_start + SZ_4M;

	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO
			"binder_mmap: %d %lx-%lx (%ld K) vma %lx pagep %lx\n",
			proc->pid, vma->vm_start, vma->vm_end,
			(vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
			(unsigned long)pgprot_val(vma->vm_page_prot));

	// 检查进程要映射的用户地址空间是否可写
	// FORBIDDEN_MMAP_FLAGS是一个宏
	// Binder驱动为进程分配的内核缓冲区在用户空间只可以读不可以写
	if (vma->vm_flags & FORBIDDEN_MMAP_FLAGS) {
		ret = -EPERM;
		failure_string = "bad vm_flags";
		goto err_bad_arg;
	}
	// 同时也禁止拷贝
	vma->vm_flags = (vma->vm_flags | VM_DONTCOPY) & ~VM_MAYWRITE;

	// 是否重复调用函数mmap来映射/dev/binder
	// 如何proc->buffer已经指向了一块内核缓冲区就会出错返回
	if (proc->buffer) {
		ret = -EBUSY;
		failure_string = "already mapped";
		goto err_already_mapped;
	}

	// 在进程的内核地址空间分配一段大小为4M的空间
	// 如果分配成功就将它的起始地址以及大小保存在proc->buffer和proc->buffer_size中
	area = get_vm_area(vma->vm_end - vma->vm_start, VM_IOREMAP);
	if (area == NULL) {
		ret = -ENOMEM;
		failure_string = "get_vm_area";
		goto err_get_vm_area_failed;
	}
	proc->buffer = area->addr;
	// 计算要映射的用户空间起始地址与前面获得的内核空间起始地址的差值
	proc->user_buffer_offset = vma->vm_start - (uintptr_t)proc->buffer;

#ifdef CONFIG_CPU_CACHE_VIPT
	if (cache_is_vipt_aliasing()) {
		while (CACHE_COLOUR((vma->vm_start ^ (uint32_t)proc->buffer))) {
			printk(KERN_INFO "binder_mmap: %d %lx-%lx maps %p bad alignment\n", proc->pid, vma->vm_start, vma->vm_end, proc->buffer);
			vma->vm_start += PAGE_SIZE;
		}
	}
#endif
	// 接下来为进程要映射的虚拟地址空间vma和area分配物理页面
	// 分配内核缓冲区
	// 创建一个物理页面结构体指针数组
	// 每一页虚拟地址空间都对应有一个物理页面
	// PAGE_SIZE一般定义为4K
	proc->pages = kzalloc(sizeof(proc->pages[0]) * ((vma->vm_end - vma->vm_start) / PAGE_SIZE), GFP_KERNEL);
	if (proc->pages == NULL) {
		ret = -ENOMEM;
		failure_string = "alloc page array";
		goto err_alloc_pages_failed;
	}
	proc->buffer_size = vma->vm_end - vma->vm_start;

	// 指定它的打开和关闭函数为binder_vma_open和binder_vma_close
	vma->vm_ops = &binder_vm_ops;
	vma->vm_private_data = proc;
	// 为虚拟地址空间area分配一个物理页面，对应的内核地址空间为proc->buffer~(proc->buffer + PAGE_SIZE)
	if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PAGE_SIZE, vma)) {
		ret = -ENOMEM;
		failure_string = "alloc small buf";
		goto err_alloc_small_buf_failed;
	}
	// 调用成功后，就使用一个binder_buffer结构体来描述它，并且将它加入到进程结构体proc中的内核缓冲区列表buffers中
	buffer = proc->buffer;
	INIT_LIST_HEAD(&proc->buffers);
	list_add(&buffer->entry, &proc->buffers);
	buffer->free = 1;
	// 调用函数将它加入到进程结构体proc的空闲内核缓冲区红黑树free_buffers中
	binder_insert_free_buffer(proc, buffer);
	// 分配线程最大用于异步事务的内核缓冲区大小为内核缓冲区的一般
	// 防止异步事务消耗过多的内核缓冲区，从而影响同步事务的执行
	proc->free_async_space = proc->buffer_size / 2;
	barrier();
	proc->files = get_files_struct(current);
	proc->vma = vma;

	/*printk(KERN_INFO "binder_mmap: %d %lx-%lx maps %p\n", proc->pid, vma->vm_start, vma->vm_end, proc->buffer);*/
	return 0;

err_alloc_small_buf_failed:
	kfree(proc->pages);
	proc->pages = NULL;
err_alloc_pages_failed:
	vfree(proc->buffer);
	proc->buffer = NULL;
err_get_vm_area_failed:
err_already_mapped:
err_bad_arg:
	printk(KERN_ERR "binder_mmap: %d %lx-%lx %s failed %d\n", proc->pid, vma->vm_start, vma->vm_end, failure_string, ret);
	return ret;
}

// 在使用Binder进程通信机制之前，首先要调用函数open打开设备文件/dev/binder来获得一个文件描述符
// 通过这个文件描述符才能和Binder驱动程序交互，继而和其他进程执行Binder进程间通信
static int binder_open(struct inode *nodp, struct file *filp)
{
	struct binder_proc *proc;

	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO "binder_open: %d:%d\n", current->group_leader->pid, current->pid);

	// 为进程创建一个binder_proc结构体
	// 进行初始化
	proc = kzalloc(sizeof(*proc), GFP_KERNEL);
	if (proc == NULL)
		return -ENOMEM;
	get_task_struct(current);
	// 任务控制块
	proc->tsk = current;
	INIT_LIST_HEAD(&proc->todo);
	init_waitqueue_head(&proc->wait);
	// 进程优先级
	proc->default_priority = task_nice(current);
	mutex_lock(&binder_lock);
	binder_stats.obj_created[BINDER_STAT_PROC]++;
	// 将结构体proc加入到全局hash队列binder_procs中
	// 驱动将所有打开了设备文件/dev/binder的进程都加入到全局hash队列binder_procs中
	// 通过这个hash队列可以知道系统当前有多少个进程在使用Binder进程间通信机制
	hlist_add_head(&proc->proc_node, &binder_procs);
	// 进程组ID
	proc->pid = current->group_leader->pid;
	INIT_LIST_HEAD(&proc->delivered_death);
	// 将初始化完成之后的binder_proc结构体proc保存在参数filp成员变量的private_data中
	// 参数filp指向一个打开文件结构体
	// 当进程调用函数open打开设备文件/dev/binder之后，内核就会返回一个文件描述符给进程
	// 这个文件描述符与参数filp所指向的打开文件结构体是关联在一起的
	// 当进程后面以这个文件描述符为参数调用函数mmap或者ioctl来与binder驱动交互时
	// 内核就会将与该文件描述符相关联的打开文件结构体传递给Binder驱动程序
	// 这时驱动可以通过它的成员变量private_data来获得前面在函数binder_open中为进程创建的binder_proc结构体proc
	filp->private_data = proc;
	mutex_unlock(&binder_lock);

	// 创建一个以进程ID为名称的只读文件
	// 以函数binder_read_proc_proc作为它的文件内容读取函数
	// 通过读取文件/proc/binder/proc/<PID>的内容，可以获取该进程的Binder线程池、实体对象、引用对象、内核缓冲区等信息
	if (binder_proc_dir_entry_proc) {
		char strbuf[11];
		snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
		remove_proc_entry(strbuf, binder_proc_dir_entry_proc);
		create_proc_read_entry(strbuf, S_IRUGO, binder_proc_dir_entry_proc, binder_read_proc_proc, proc);
	}

	return 0;
}

static int binder_flush(struct file *filp, fl_owner_t id)
{
	struct binder_proc *proc = filp->private_data;

	binder_defer_work(proc, BINDER_DEFERRED_FLUSH);

	return 0;
}

static void binder_deferred_flush(struct binder_proc *proc)
{
	struct rb_node *n;
	int wake_count = 0;
	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n)) {
		struct binder_thread *thread = rb_entry(n, struct binder_thread, rb_node);
		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		if (thread->looper & BINDER_LOOPER_STATE_WAITING) {
			wake_up_interruptible(&thread->wait);
			wake_count++;
		}
	}
	wake_up_interruptible_all(&proc->wait);

	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO "binder_flush: %d woke %d threads\n", proc->pid, wake_count);
}

// Server进程本来就应该常驻在系统中为Client进程提供服务
// 但是如果出现异常导致它退出
// 退出之后运行在它里面的Binder本地对象就意外死亡了
// 这时候Binder驱动程序就应该向那些引用了它的Binder代理对象发送死亡接收通知
// 以便告知它们引用了一个无效的Binder本地对象
//
// Binder驱动程序将设备文件/dev/binder的释放操作设置为函数binder_release
// Server进程在启动时，会调用函数open来打开这个设备文件/dev/binder
// 在退出时，它会调用函数close来关闭设备文件/dev/binder
// 这时候，binder_release会被调用
// 如果Binder异常退出且没有正常关闭/dev/binder，那么内核就会负责关闭它，这时候也会触发函数binder_release被调用
// 因此，Binder驱动程序就可以在函数binder_release中检查进程退出时是否有Binder本地对象在里面运行
// 如果有，说明它们是死亡了的Binder本地对象
static int binder_release(struct inode *nodp, struct file *filp)
{
	// 除了检查进程中是否有Binder本地对象在运行之外，还会释放进程所占用的资源
	struct binder_proc *proc = filp->private_data;
	if (binder_proc_dir_entry_proc) {
		char strbuf[11];
		snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
		remove_proc_entry(strbuf, binder_proc_dir_entry_proc);
	}

	// 调用函数，将BINDER_DEFERRED_RELEASE类型的延迟操作添加到一个全局的hash列表中
	binder_defer_work(proc, BINDER_DEFERRED_RELEASE);

	return 0;
}

static void binder_deferred_release(struct binder_proc *proc)
{
	struct hlist_node *pos;
	struct binder_transaction *t;
	struct rb_node *n;
	int threads, nodes, incoming_refs, outgoing_refs, buffers, active_transactions, page_count;

	BUG_ON(proc->vma);
	BUG_ON(proc->files);

	hlist_del(&proc->proc_node);
	if (binder_context_mgr_node && binder_context_mgr_node->proc == proc) {
		if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
			printk(KERN_INFO "binder_release: %d context_mgr_node gone\n", proc->pid);
		binder_context_mgr_node = NULL;
	}

	threads = 0;
	active_transactions = 0;
	while ((n = rb_first(&proc->threads))) {
		struct binder_thread *thread = rb_entry(n, struct binder_thread, rb_node);
		threads++;
		active_transactions += binder_free_thread(proc, thread);
	}
	nodes = 0;
	incoming_refs = 0;
	// 循环检查目标进程proc的Binder实体对象列表nodes的每一个Binder实体对象
	// 如果这些Binder实体对象的Binder引用对象列表refs不为空
	while ((n = rb_first(&proc->nodes))) {
		struct binder_node *node = rb_entry(n, struct binder_node, rb_node);

		nodes++;
		rb_erase(&node->rb_node, &proc->nodes);
		list_del_init(&node->work.entry);
		if (hlist_empty(&node->refs)) {
			kfree(node);
			binder_stats.obj_deleted[BINDER_STAT_NODE]++;
		} else {
			struct binder_ref *ref;
			int death = 0;

			node->proc = NULL;
			node->local_strong_refs = 0;
			node->local_weak_refs = 0;
			hlist_add_head(&node->dead_node, &binder_dead_nodes);

			hlist_for_each_entry(ref, pos, &node->refs, node_entry) {
				incoming_refs++;
				// 循环检查这些引用对象成员变量death是否不等于NULL
				if (ref->death) {
					// 如果是，则注册过死亡接收通知
					death++;
					if (list_empty(&ref->death->work.entry)) {
						// 将BINDER_WORK_DEAD_BINDER工作项添加到对应的Client进程的todo队列中
						ref->death->work.type = BINDER_WORK_DEAD_BINDER;
						list_add_tail(&ref->death->work.entry, &ref->proc->todo);
						// 唤醒Client进程的Binder线程来处理这些死亡接收者
						wake_up_interruptible(&ref->proc->wait);
					} else
						BUG();
				}
			}
			if (binder_debug_mask & BINDER_DEBUG_DEAD_BINDER)
				printk(KERN_INFO "binder: node %d now dead, refs %d, death %d\n", node->debug_id, incoming_refs, death);
		}
	}
	outgoing_refs = 0;
	while ((n = rb_first(&proc->refs_by_desc))) {
		struct binder_ref *ref = rb_entry(n, struct binder_ref, rb_node_desc);
		outgoing_refs++;
		binder_delete_ref(ref);
	}
	binder_release_work(&proc->todo);
	buffers = 0;

	while ((n = rb_first(&proc->allocated_buffers))) {
		struct binder_buffer *buffer = rb_entry(n, struct binder_buffer, rb_node);
		t = buffer->transaction;
		if (t) {
			t->buffer = NULL;
			buffer->transaction = NULL;
			printk(KERN_ERR "binder: release proc %d, transaction %d, not freed\n", proc->pid, t->debug_id);
			/*BUG();*/
		}
		binder_free_buf(proc, buffer);
		buffers++;
	}

	binder_stats.obj_deleted[BINDER_STAT_PROC]++;

	page_count = 0;
	if (proc->pages) {
		int i;
		for (i = 0; i < proc->buffer_size / PAGE_SIZE; i++) {
			if (proc->pages[i]) {
				if (binder_debug_mask & BINDER_DEBUG_BUFFER_ALLOC)
					printk(KERN_INFO "binder_release: %d: page %d at %p not freed\n", proc->pid, i, proc->buffer + i * PAGE_SIZE);
				__free_page(proc->pages[i]);
				page_count++;
			}
		}
		kfree(proc->pages);
		vfree(proc->buffer);
	}

	put_task_struct(proc->tsk);

	if (binder_debug_mask & BINDER_DEBUG_OPEN_CLOSE)
		printk(KERN_INFO "binder_release: %d threads %d, nodes %d (ref %d), refs %d, active transactions %d, buffers %d, pages %d\n",
		       proc->pid, threads, nodes, incoming_refs, outgoing_refs, active_transactions, buffers, page_count);

	kfree(proc);
}

static void binder_deferred_func(struct work_struct *work)
{
	struct binder_proc *proc;
	struct files_struct *files;

	int defer;
	do {
		mutex_lock(&binder_lock);
		mutex_lock(&binder_deferred_lock);
		if (!hlist_empty(&binder_deferred_list)) {
			proc = hlist_entry(binder_deferred_list.first,
					struct binder_proc, deferred_work_node);
			hlist_del_init(&proc->deferred_work_node);
			defer = proc->deferred_work;
			proc->deferred_work = 0;
		} else {
			proc = NULL;
			defer = 0;
		}
		mutex_unlock(&binder_deferred_lock);

		files = NULL;
		if (defer & BINDER_DEFERRED_PUT_FILES)
			if ((files = proc->files))
				proc->files = NULL;

		if (defer & BINDER_DEFERRED_FLUSH)
			binder_deferred_flush(proc);

		if (defer & BINDER_DEFERRED_RELEASE)
			binder_deferred_release(proc); /* frees proc */

		mutex_unlock(&binder_lock);
		if (files)
			put_files_struct(files);
	} while (proc);
}
static DECLARE_WORK(binder_deferred_work, binder_deferred_func);

static void binder_defer_work(struct binder_proc *proc, int defer)
{
	mutex_lock(&binder_deferred_lock);
	proc->deferred_work |= defer;
	if (hlist_unhashed(&proc->deferred_work_node)) {
		hlist_add_head(&proc->deferred_work_node,
				&binder_deferred_list);
		schedule_work(&binder_deferred_work);
	}
	mutex_unlock(&binder_deferred_lock);
}

static char *print_binder_transaction(char *buf, char *end, const char *prefix, struct binder_transaction *t)
{
	buf += snprintf(buf, end - buf, "%s %d: %p from %d:%d to %d:%d code %x flags %x pri %ld r%d",
			prefix, t->debug_id, t, t->from ? t->from->proc->pid : 0,
			t->from ? t->from->pid : 0,
			t->to_proc ? t->to_proc->pid : 0,
			t->to_thread ? t->to_thread->pid : 0,
			t->code, t->flags, t->priority, t->need_reply);
	if (buf >= end)
		return buf;
	if (t->buffer == NULL) {
		buf += snprintf(buf, end - buf, " buffer free\n");
		return buf;
	}
	if (t->buffer->target_node) {
		buf += snprintf(buf, end - buf, " node %d",
				t->buffer->target_node->debug_id);
		if (buf >= end)
			return buf;
	}
	buf += snprintf(buf, end - buf, " size %zd:%zd data %p\n",
			t->buffer->data_size, t->buffer->offsets_size,
			t->buffer->data);
	return buf;
}

static char *print_binder_buffer(char *buf, char *end, const char *prefix, struct binder_buffer *buffer)
{
	buf += snprintf(buf, end - buf, "%s %d: %p size %zd:%zd %s\n",
			prefix, buffer->debug_id, buffer->data,
			buffer->data_size, buffer->offsets_size,
			buffer->transaction ? "active" : "delivered");
	return buf;
}

static char *print_binder_work(char *buf, char *end, const char *prefix,
	const char *transaction_prefix, struct binder_work *w)
{
	struct binder_node *node;
	struct binder_transaction *t;

	switch (w->type) {
	case BINDER_WORK_TRANSACTION:
		t = container_of(w, struct binder_transaction, work);
		buf = print_binder_transaction(buf, end, transaction_prefix, t);
		break;
	case BINDER_WORK_TRANSACTION_COMPLETE:
		buf += snprintf(buf, end - buf,
				"%stransaction complete\n", prefix);
		break;
	case BINDER_WORK_NODE:
		node = container_of(w, struct binder_node, work);
		buf += snprintf(buf, end - buf, "%snode work %d: u%p c%p\n",
				prefix, node->debug_id, node->ptr, node->cookie);
		break;
	case BINDER_WORK_DEAD_BINDER:
		buf += snprintf(buf, end - buf, "%shas dead binder\n", prefix);
		break;
	case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
		buf += snprintf(buf, end - buf,
				"%shas cleared dead binder\n", prefix);
		break;
	case BINDER_WORK_CLEAR_DEATH_NOTIFICATION:
		buf += snprintf(buf, end - buf,
				"%shas cleared death notification\n", prefix);
		break;
	default:
		buf += snprintf(buf, end - buf, "%sunknown work: type %d\n",
				prefix, w->type);
		break;
	}
	return buf;
}

static char *print_binder_thread(char *buf, char *end, struct binder_thread *thread, int print_always)
{
	struct binder_transaction *t;
	struct binder_work *w;
	char *start_buf = buf;
	char *header_buf;

	buf += snprintf(buf, end - buf, "  thread %d: l %02x\n", thread->pid, thread->looper);
	header_buf = buf;
	t = thread->transaction_stack;
	while (t) {
		if (buf >= end)
			break;
		if (t->from == thread) {
			buf = print_binder_transaction(buf, end, "    outgoing transaction", t);
			t = t->from_parent;
		} else if (t->to_thread == thread) {
			buf = print_binder_transaction(buf, end, "    incoming transaction", t);
			t = t->to_parent;
		} else {
			buf = print_binder_transaction(buf, end, "    bad transaction", t);
			t = NULL;
		}
	}
	list_for_each_entry(w, &thread->todo, entry) {
		if (buf >= end)
			break;
		buf = print_binder_work(buf, end, "    ",
					"    pending transaction", w);
	}
	if (!print_always && buf == header_buf)
		buf = start_buf;
	return buf;
}

static char *print_binder_node(char *buf, char *end, struct binder_node *node)
{
	struct binder_ref *ref;
	struct hlist_node *pos;
	struct binder_work *w;
	int count;
	count = 0;
	hlist_for_each_entry(ref, pos, &node->refs, node_entry)
		count++;

	buf += snprintf(buf, end - buf, "  node %d: u%p c%p hs %d hw %d ls %d lw %d is %d iw %d",
			node->debug_id, node->ptr, node->cookie,
			node->has_strong_ref, node->has_weak_ref,
			node->local_strong_refs, node->local_weak_refs,
			node->internal_strong_refs, count);
	if (buf >= end)
		return buf;
	if (count) {
		buf += snprintf(buf, end - buf, " proc");
		if (buf >= end)
			return buf;
		hlist_for_each_entry(ref, pos, &node->refs, node_entry) {
			buf += snprintf(buf, end - buf, " %d", ref->proc->pid);
			if (buf >= end)
				return buf;
		}
	}
	buf += snprintf(buf, end - buf, "\n");
	list_for_each_entry(w, &node->async_todo, entry) {
		if (buf >= end)
			break;
		buf = print_binder_work(buf, end, "    ",
					"    pending async transaction", w);
	}
	return buf;
}

static char *print_binder_ref(char *buf, char *end, struct binder_ref *ref)
{
	buf += snprintf(buf, end - buf, "  ref %d: desc %d %snode %d s %d w %d d %p\n",
			ref->debug_id, ref->desc, ref->node->proc ? "" : "dead ",
			ref->node->debug_id, ref->strong, ref->weak, ref->death);
	return buf;
}

static char *print_binder_proc(char *buf, char *end, struct binder_proc *proc, int print_all)
{
	struct binder_work *w;
	struct rb_node *n;
	char *start_buf = buf;
	char *header_buf;

	buf += snprintf(buf, end - buf, "proc %d\n", proc->pid);
	header_buf = buf;

	for (n = rb_first(&proc->threads); n != NULL && buf < end; n = rb_next(n))
		buf = print_binder_thread(buf, end, rb_entry(n, struct binder_thread, rb_node), print_all);
	for (n = rb_first(&proc->nodes); n != NULL && buf < end; n = rb_next(n)) {
		struct binder_node *node = rb_entry(n, struct binder_node, rb_node);
		if (print_all || node->has_async_transaction)
			buf = print_binder_node(buf, end, node);
	}
	if (print_all) {
		for (n = rb_first(&proc->refs_by_desc); n != NULL && buf < end; n = rb_next(n))
			buf = print_binder_ref(buf, end, rb_entry(n, struct binder_ref, rb_node_desc));
	}
	for (n = rb_first(&proc->allocated_buffers); n != NULL && buf < end; n = rb_next(n))
		buf = print_binder_buffer(buf, end, "  buffer", rb_entry(n, struct binder_buffer, rb_node));
	list_for_each_entry(w, &proc->todo, entry) {
		if (buf >= end)
			break;
		buf = print_binder_work(buf, end, "  ",
					"  pending transaction", w);
	}
	list_for_each_entry(w, &proc->delivered_death, entry) {
		if (buf >= end)
			break;
		buf += snprintf(buf, end - buf, "  has delivered dead binder\n");
		break;
	}
	if (!print_all && buf == header_buf)
		buf = start_buf;
	return buf;
}

static const char *binder_return_strings[] = {
	"BR_ERROR",
	"BR_OK",
	"BR_TRANSACTION",
	"BR_REPLY",
	"BR_ACQUIRE_RESULT",
	"BR_DEAD_REPLY",
	"BR_TRANSACTION_COMPLETE",
	"BR_INCREFS",
	"BR_ACQUIRE",
	"BR_RELEASE",
	"BR_DECREFS",
	"BR_ATTEMPT_ACQUIRE",
	"BR_NOOP",
	"BR_SPAWN_LOOPER",
	"BR_FINISHED",
	"BR_DEAD_BINDER",
	"BR_CLEAR_DEATH_NOTIFICATION_DONE",
	"BR_FAILED_REPLY"
};

static const char *binder_command_strings[] = {
	"BC_TRANSACTION",
	"BC_REPLY",
	"BC_ACQUIRE_RESULT",
	"BC_FREE_BUFFER",
	"BC_INCREFS",
	"BC_ACQUIRE",
	"BC_RELEASE",
	"BC_DECREFS",
	"BC_INCREFS_DONE",
	"BC_ACQUIRE_DONE",
	"BC_ATTEMPT_ACQUIRE",
	"BC_REGISTER_LOOPER",
	"BC_ENTER_LOOPER",
	"BC_EXIT_LOOPER",
	"BC_REQUEST_DEATH_NOTIFICATION",
	"BC_CLEAR_DEATH_NOTIFICATION",
	"BC_DEAD_BINDER_DONE"
};

static const char *binder_objstat_strings[] = {
	"proc",
	"thread",
	"node",
	"ref",
	"death",
	"transaction",
	"transaction_complete"
};

static char *print_binder_stats(char *buf, char *end, const char *prefix, struct binder_stats *stats)
{
	int i;

	BUILD_BUG_ON(ARRAY_SIZE(stats->bc) != ARRAY_SIZE(binder_command_strings));
	for (i = 0; i < ARRAY_SIZE(stats->bc); i++) {
		if (stats->bc[i])
			buf += snprintf(buf, end - buf, "%s%s: %d\n", prefix,
					binder_command_strings[i], stats->bc[i]);
		if (buf >= end)
			return buf;
	}

	BUILD_BUG_ON(ARRAY_SIZE(stats->br) != ARRAY_SIZE(binder_return_strings));
	for (i = 0; i < ARRAY_SIZE(stats->br); i++) {
		if (stats->br[i])
			buf += snprintf(buf, end - buf, "%s%s: %d\n", prefix,
					binder_return_strings[i], stats->br[i]);
		if (buf >= end)
			return buf;
	}

	BUILD_BUG_ON(ARRAY_SIZE(stats->obj_created) != ARRAY_SIZE(binder_objstat_strings));
	BUILD_BUG_ON(ARRAY_SIZE(stats->obj_created) != ARRAY_SIZE(stats->obj_deleted));
	for (i = 0; i < ARRAY_SIZE(stats->obj_created); i++) {
		if (stats->obj_created[i] || stats->obj_deleted[i])
			buf += snprintf(buf, end - buf, "%s%s: active %d total %d\n", prefix,
					binder_objstat_strings[i],
					stats->obj_created[i] - stats->obj_deleted[i],
					stats->obj_created[i]);
		if (buf >= end)
			return buf;
	}
	return buf;
}

static char *print_binder_proc_stats(char *buf, char *end, struct binder_proc *proc)
{
	struct binder_work *w;
	struct rb_node *n;
	int count, strong, weak;

	buf += snprintf(buf, end - buf, "proc %d\n", proc->pid);
	if (buf >= end)
		return buf;
	count = 0;
	for (n = rb_first(&proc->threads); n != NULL; n = rb_next(n))
		count++;
	buf += snprintf(buf, end - buf, "  threads: %d\n", count);
	if (buf >= end)
		return buf;
	buf += snprintf(buf, end - buf, "  requested threads: %d+%d/%d\n"
			"  ready threads %d\n"
			"  free async space %zd\n", proc->requested_threads,
			proc->requested_threads_started, proc->max_threads,
			proc->ready_threads, proc->free_async_space);
	if (buf >= end)
		return buf;
	count = 0;
	for (n = rb_first(&proc->nodes); n != NULL; n = rb_next(n))
		count++;
	buf += snprintf(buf, end - buf, "  nodes: %d\n", count);
	if (buf >= end)
		return buf;
	count = 0;
	strong = 0;
	weak = 0;
	for (n = rb_first(&proc->refs_by_desc); n != NULL; n = rb_next(n)) {
		struct binder_ref *ref = rb_entry(n, struct binder_ref, rb_node_desc);
		count++;
		strong += ref->strong;
		weak += ref->weak;
	}
	buf += snprintf(buf, end - buf, "  refs: %d s %d w %d\n", count, strong, weak);
	if (buf >= end)
		return buf;

	count = 0;
	for (n = rb_first(&proc->allocated_buffers); n != NULL; n = rb_next(n))
		count++;
	buf += snprintf(buf, end - buf, "  buffers: %d\n", count);
	if (buf >= end)
		return buf;

	count = 0;
	list_for_each_entry(w, &proc->todo, entry) {
		switch (w->type) {
		case BINDER_WORK_TRANSACTION:
			count++;
			break;
		default:
			break;
		}
	}
	buf += snprintf(buf, end - buf, "  pending transactions: %d\n", count);
	if (buf >= end)
		return buf;

	buf = print_binder_stats(buf, end, "  ", &proc->stats);

	return buf;
}


static int binder_read_proc_state(
	char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct binder_proc *proc;
	struct hlist_node *pos;
	struct binder_node *node;
	int len = 0;
	char *buf = page;
	char *end = page + PAGE_SIZE;
	int do_lock = !binder_debug_no_lock;

	if (off)
		return 0;

	if (do_lock)
		mutex_lock(&binder_lock);

	buf += snprintf(buf, end - buf, "binder state:\n");

	if (!hlist_empty(&binder_dead_nodes))
		buf += snprintf(buf, end - buf, "dead nodes:\n");
	hlist_for_each_entry(node, pos, &binder_dead_nodes, dead_node) {
		if (buf >= end)
			break;
		buf = print_binder_node(buf, end, node);
	}

	hlist_for_each_entry(proc, pos, &binder_procs, proc_node) {
		if (buf >= end)
			break;
		buf = print_binder_proc(buf, end, proc, 1);
	}
	if (do_lock)
		mutex_unlock(&binder_lock);
	if (buf > page + PAGE_SIZE)
		buf = page + PAGE_SIZE;

	*start = page + off;

	len = buf - page;
	if (len > off)
		len -= off;
	else
		len = 0;

	return len < count ? len  : count;
}

static int binder_read_proc_stats(
	char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct binder_proc *proc;
	struct hlist_node *pos;
	int len = 0;
	char *p = page;
	int do_lock = !binder_debug_no_lock;

	if (off)
		return 0;

	if (do_lock)
		mutex_lock(&binder_lock);

	p += snprintf(p, PAGE_SIZE, "binder stats:\n");

	p = print_binder_stats(p, page + PAGE_SIZE, "", &binder_stats);

	hlist_for_each_entry(proc, pos, &binder_procs, proc_node) {
		if (p >= page + PAGE_SIZE)
			break;
		p = print_binder_proc_stats(p, page + PAGE_SIZE, proc);
	}
	if (do_lock)
		mutex_unlock(&binder_lock);
	if (p > page + PAGE_SIZE)
		p = page + PAGE_SIZE;

	*start = page + off;

	len = p - page;
	if (len > off)
		len -= off;
	else
		len = 0;

	return len < count ? len  : count;
}

static int binder_read_proc_transactions(
	char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct binder_proc *proc;
	struct hlist_node *pos;
	int len = 0;
	char *buf = page;
	char *end = page + PAGE_SIZE;
	int do_lock = !binder_debug_no_lock;

	if (off)
		return 0;

	if (do_lock)
		mutex_lock(&binder_lock);

	buf += snprintf(buf, end - buf, "binder transactions:\n");
	hlist_for_each_entry(proc, pos, &binder_procs, proc_node) {
		if (buf >= end)
			break;
		buf = print_binder_proc(buf, end, proc, 0);
	}
	if (do_lock)
		mutex_unlock(&binder_lock);
	if (buf > page + PAGE_SIZE)
		buf = page + PAGE_SIZE;

	*start = page + off;

	len = buf - page;
	if (len > off)
		len -= off;
	else
		len = 0;

	return len < count ? len  : count;
}

static int binder_read_proc_proc(
	char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct binder_proc *proc = data;
	int len = 0;
	char *p = page;
	int do_lock = !binder_debug_no_lock;

	if (off)
		return 0;

	if (do_lock)
		mutex_lock(&binder_lock);
	p += snprintf(p, PAGE_SIZE, "binder proc state:\n");
	p = print_binder_proc(p, page + PAGE_SIZE, proc, 1);
	if (do_lock)
		mutex_unlock(&binder_lock);

	if (p > page + PAGE_SIZE)
		p = page + PAGE_SIZE;
	*start = page + off;

	len = p - page;
	if (len > off)
		len -= off;
	else
		len = 0;

	return len < count ? len  : count;
}

static char *print_binder_transaction_log_entry(char *buf, char *end, struct binder_transaction_log_entry *e)
{
	buf += snprintf(buf, end - buf, "%d: %s from %d:%d to %d:%d node %d handle %d size %d:%d\n",
			e->debug_id, (e->call_type == 2) ? "reply" :
			((e->call_type == 1) ? "async" : "call "), e->from_proc,
			e->from_thread, e->to_proc, e->to_thread, e->to_node,
			e->target_handle, e->data_size, e->offsets_size);
	return buf;
}

static int binder_read_proc_transaction_log(
	char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct binder_transaction_log *log = data;
	int len = 0;
	int i;
	char *buf = page;
	char *end = page + PAGE_SIZE;

	if (off)
		return 0;

	if (log->full) {
		for (i = log->next; i < ARRAY_SIZE(log->entry); i++) {
			if (buf >= end)
				break;
			buf = print_binder_transaction_log_entry(buf, end, &log->entry[i]);
		}
	}
	for (i = 0; i < log->next; i++) {
		if (buf >= end)
			break;
		buf = print_binder_transaction_log_entry(buf, end, &log->entry[i]);
	}

	*start = page + off;

	len = buf - page;
	if (len > off)
		len -= off;
	else
		len = 0;

	return len < count ? len  : count;
}

// 设备文件的操作方法列表
static struct file_operations binder_fops = {
	.owner = THIS_MODULE,
	.poll = binder_poll,
	// IO控制函数
	.unlocked_ioctl = binder_ioctl,
	// 内存映射
	.mmap = binder_mmap,
	// 打开
	.open = binder_open,
	.flush = binder_flush,
	.release = binder_release,
};

static struct miscdevice binder_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "binder",
	.fops = &binder_fops
};

static int __init binder_init(void)
{
	int ret;

	// 在目标设备上创建一个/proc/binder/proc的目录
	// 每一个使用了Binder进程间通信机制的进程在该目录下都对应有一个文件，这些文件以进程ID来命名，通过它们
	// 可以读取到各个进程的Binder线程池、Binder实体对象、Binder引用对象以及内核缓冲区等信息
	binder_proc_dir_entry_root = proc_mkdir("binder", NULL);
	if (binder_proc_dir_entry_root)
		binder_proc_dir_entry_proc = proc_mkdir("proc", binder_proc_dir_entry_root);
	// 创建一个Binder设备
	// 创建一个misc类型的字符设备
	ret = misc_register(&binder_miscdev);
	// 创建/proc/binder目录下创建五个文件
	// 读取这五个文件可以读取Binder驱动程序的运行状况
	// 例如，BC,BR的请求次数、日志记录信息、正在执行进程间通信过程的进程信息等等
	if (binder_proc_dir_entry_root) {
		create_proc_read_entry("state", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_state, NULL);
		create_proc_read_entry("stats", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_stats, NULL);
		create_proc_read_entry("transactions", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_transactions, NULL);
		create_proc_read_entry("transaction_log", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_transaction_log, &binder_transaction_log);
		create_proc_read_entry("failed_transaction_log", S_IRUGO, binder_proc_dir_entry_root, binder_read_proc_transaction_log, &binder_transaction_log_failed);
	}
	return ret;
}

device_initcall(binder_init);

MODULE_LICENSE("GPL v2");
