static int do_report_event(void __user *arg)
{
    static bool services_started = false;
    struct ksu_report_event_cmd cmd;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    switch (cmd.event) {
    case EVENT_POST_FS_DATA: {
        static bool post_fs_data_lock = false;

        // Reset for emulated soft reboot
        services_started = false;
        if (!post_fs_data_lock) {
            post_fs_data_lock = true;
            if (ksu_late_loaded) {
                pr_info("post-fs-data skipped (late load)\n");
            } else {
                pr_info("post-fs-data triggered\n");
                on_post_fs_data();
            }
        }
        break;
    }
    case EVENT_BOOT_COMPLETED: {
        static bool boot_complete_lock = false;
        if (!boot_complete_lock) {
            boot_complete_lock = true;
            if (ksu_late_loaded) {
                pr_info("boot_complete skipped (late load)\n");
            } else {
                pr_info("boot_complete triggered\n");
                on_boot_completed();
#ifdef CONFIG_KSU_SUSFS
                susfs_start_sdcard_monitor_fn();
#endif
            }
        }
        break;
    }
    case EVENT_MODULE_MOUNTED: {
        pr_info("module mounted!\n");
        on_module_mounted();
        break;
    }
    case EVENT_SERVICES: {
        if (services_started) {
            pr_info("services already started, skipping\n");
            return 0;
        }
        services_started = true;
        pr_info("services triggered\n");
        return 1;
    }
    default:
        break;
    }

    return 0;
}
