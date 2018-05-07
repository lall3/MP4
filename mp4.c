#define pr_fmt(fmt) "cs423_mp4: " fmt

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
#include "mp4_given.h"

//added inclusion
#include <linux/slab.h>

/**
 * get_inode_sid - Get the inode mp4 security label id
 *
 * @inode: the input inode
 *
 * @return the inode's security id if found.
 *
 */
static int get_inode_sid(struct inode *inode)
{
	struct dentry * d_entry;
	int sid;
	char * buff;
	int xttr_value;

	buff = kmalloc(128, GFP_KERNEL);

	if (!buff)
		return 0;
	
	
	d_entry = d_find_alias(inode);
	if (d_entry == NULL)
		return -ENOENT;
	
	xttr_value = inode->i_op->getxattr(d_entry, XATTR_NAME_MP4, buff, 128);

	dput(dentry);
	if (xttr_value == -ERANGE) 
	{
		dput(dentry);
		kfree(buff);
		return 0;
	}
	

	buff[xttr_value]='\0'; //check
	sid = __cred_ctx_to_sid(buff);
	dput(dentry);

	//pr_info("SID: %d\n", sid);

	return sid;
}//DONE

/**
 * mp4_bprm_set_creds - Set the credentials for a new task
 *
 * @bprm: The linux binary preparation structure
 *
 * returns 0 on success.
 */
static int mp4_bprm_set_creds(struct linux_binprm *bprm)
{
	/*
	 * Add your code here
	 * ...
	 */
	int sid;
	struct inode *curr_inode = bprm->file->f_path.dentry->d_inode;
	struct mp4_security * new_sec_struct = (struct mp4_security*)kzalloc(sizeof(struct mp4_security), gfp);

	sid = get_inode_sid(curr_inode);
	if(sid != MP4_TARGET_SID)
		return 0;

	new_sec_struct->level = MP4_TARGET_SID;
	new_sec_struct->mp4_flags = MP4_TARGET_SID;
	bprm->cred->security = new_sec_struct;

	return 0;
}//DONE

/**
 * mp4_cred_alloc_blank - Allocate a blank mp4 security label
 *
 * @cred: the new credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{

	struct mp4_security *temp= (struct mp4_security*)kzalloc(sizeof(struct mp4_security), gfp);
	temp->level = MP4_NO_ACCESS; 

	if (!temp)
		return -ENOMEM;

	cred->security = temp;

	return 0;
}//DONE


/**
 * mp4_cred_free - Free a created security label
 *
 * @cred: the credentials struct
 *
 */
static void mp4_cred_free(struct cred *cred)
{
	struct mp4_security *temp = cred->security;
	kfree(temp);
}//DONE

/**
 * mp4_cred_prepare - Prepare new credentials for modification
 *
 * @new: the new credentials
 * @old: the old credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
{
	struct mp4_security * old_struct;
	struct mp4_security * new_struct;
	old_struct = old->security;

	//selinux doccumentation
	new_struct =(struct mp4_security*) (kmemdup(old_struct, sizeof(struct mp4_security), gfp));

	if(!new_struct)
		return -ENOMEM;

	new->security = new_struct;
	return 0;

}//DONE

/**
 * mp4_inode_init_security - Set the security attribute of a newly created inode
 *
 * @inode: the newly created inode
 * @dir: the containing directory
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * returns 0 if all goes well, -ENOMEM if no memory, -EOPNOTSUPP to skip
 *
 */
static int mp4_inode_init_security(struct inode *inode, struct inode *dir,
				   const struct qstr *qstr,
				   const char **name, void **value, size_t *len)
{
	/*
	 * Add your code here
	 * ...
	 */
	int sid; 
	char *pointer1 , *pointer2, *pointer3;

	if(!current_cred() || !dir || !inode)
		return -EOPNOTSUPP;

	if(!(current_cred()->security))
		return -EOPNOTSUPP;

	sid = get_inode_sid(inode);
	pointer1 = pointer2 = pointer3 = NULL;

	if(sid == MP4_TARGET_SID)
	{
		pointer1 = kstrdup(XATTR_NAME_MP4, GFP_KERNEL);
		pointer2 = kstrdup("read-write", GFP_KERNEL); 
		pointer3 = kstrdup("dir-write", GFP_KERNEL); 
		//mem check
		if(!pointer1 || !pointer2)
			return -ENOMEM;
		*name = pointer1;
		if(S_ISDIR(inode->i_mode))
			*value = pointer2;
		else
			*value = pointer3;
		*len= sizeof(XATTR_NAME_MP4);		
	}

	return 0;
}//DONE

/**
 * mp4_has_permission - Check if subject has permission to an object
 *
 * @ssid: the subject's security id
 * @osid: the object's security id
 * @mask: the operation mask
 *
 * returns 0 is access granter, -EACCES otherwise
 *
 */
static int mp4_has_permission(int ssid, int osid, int mask)
{
	/*
	 * Add your code here
	 * ...
	 */
	return 0;
}

/**
 * mp4_inode_permission - Check permission for an inode being opened
 *
 * @inode: the inode in question
 * @mask: the access requested
 *
 * This is the important access check hook
 *
 * returns 0 if access is granted, -EACCES otherwise
 *
 */
static int mp4_inode_permission(struct inode *inode, int mask)
{
	struct dentry *d_entry;

	char * d_path;

	if (mask==0)
		return -EACCES;

	d_entry = d_find_alias(inode); 
	
	if(!d_entry)
	{
		dput(d_entry);
		return -EACCES;
	}

	d_path = kmalloc(128, GFP_KERNEL);
	dentry_path(d_entry, d_path, 128);

	if (mp4_should_skip_path(path)) {
		kfree(path);
		dput(dentry);
		return -EACCES;
	}



	return 0;
}


/*
 * This is the list of hooks that we will using for our security module.
 */
static struct security_hook_list mp4_hooks[] = {
	/*
	 * inode function to assign a label and to check permission
	 */
	LSM_HOOK_INIT(inode_init_security, mp4_inode_init_security),
	LSM_HOOK_INIT(inode_permission, mp4_inode_permission),

	/*
	 * setting the credentials subjective security label when laucnhing a
	 * binary
	 */
	LSM_HOOK_INIT(bprm_set_creds, mp4_bprm_set_creds),

	/* credentials handling and preparation */
	LSM_HOOK_INIT(cred_alloc_blank, mp4_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, mp4_cred_free),
	LSM_HOOK_INIT(cred_prepare, mp4_cred_prepare)
};

static __init int mp4_init(void)
{
	/*
	 * check if mp4 lsm is enabled with boot parameters
	 */
	if (!security_module_enable("mp4"))
		return 0;

	pr_info("mp4 LSM initializing..");

	/*
	 * Register the mp4 hooks with lsm
	 */
	security_add_hooks(mp4_hooks, ARRAY_SIZE(mp4_hooks));

	return 0;
}

/*
 * early registration with the kernel
 */
security_initcall(mp4_init);
