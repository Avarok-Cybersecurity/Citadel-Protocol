package me.carda.awesome_notifications.notifications.managers;

import android.content.Context;

import com.google.common.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.List;

import me.carda.awesome_notifications.Definitions;
import me.carda.awesome_notifications.notifications.NotificationScheduler;
import me.carda.awesome_notifications.notifications.models.PushNotification;

public class ScheduleManager {

    private static final SharedManager<PushNotification> shared = new SharedManager<>("ScheduleManager", PushNotification.class);

    public static Boolean removeSchedule(Context context, PushNotification received) {
        return shared.remove(context, Definitions.SHARED_SCHEDULED_NOTIFICATIONS, received.content.id.toString());
    }

    public static List<PushNotification> listSchedules(Context context) {
        return shared.getAllObjects(context, Definitions.SHARED_SCHEDULED_NOTIFICATIONS);
    }

    public static void saveSchedule(Context context, PushNotification received) {
        shared.set(context, Definitions.SHARED_SCHEDULED_NOTIFICATIONS, received.content.id.toString(), received);
    }

    public static PushNotification getScheduleByKey(Context context, String actionKey){
        return shared.get(context, Definitions.SHARED_SCHEDULED_NOTIFICATIONS, actionKey);
    }

    public static void cancelAllSchedules(Context context) {
        List<PushNotification> listSchedules = shared.getAllObjects(context, Definitions.SHARED_SCHEDULED_NOTIFICATIONS);
        if(listSchedules != null) {
            for (PushNotification pushNotification : listSchedules) {
                NotificationScheduler.cancelNotification(context, pushNotification.content.id);
            }
        }
    }

    public static void cancelSchedule(Context context, Integer id) {
        PushNotification schedule = shared.get(context, Definitions.SHARED_SCHEDULED_NOTIFICATIONS, id.toString());
        if(schedule != null)
            removeSchedule(context, schedule);
    }

    public static void commitChanges(Context context){
        shared.commit(context);
    }
}
