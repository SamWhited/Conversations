package eu.siacs.conversations;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.ResultReceiver;
import android.support.v4.content.LocalBroadcastManager;
import android.widget.RemoteViews;

import eu.siacs.conversations.services.NotificationService;
import eu.siacs.conversations.ui.ConversationActivity;


/**
 * Implementation of App Widget functionality.
 */
public class ConversationsIconWidget extends AppWidgetProvider {

	@Override
	public void onUpdate(final Context context, final AppWidgetManager appWidgetManager, final int[] appWidgetIds) {
		// There may be multiple widgets active, so update all of them
		final LocalBroadcastManager bm = LocalBroadcastManager.getInstance(context);
		for (final int appWidgetId : appWidgetIds) {
			final Intent intent = new Intent(context, NotificationService.class);
			final RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.conversations_icon_widget);
			intent.putExtra(NotificationService.EXTRA_UNREAD_COUNT, new ResultReceiver(null) {
				@Override
				protected void onReceiveResult(final int resultCode, final Bundle resultData) {
					super.onReceiveResult(resultCode, resultData);
					updateAppWidgetText(context, appWidgetManager, appWidgetId, views,
							resultData.getInt(NotificationService.EXTRA_UNREAD_COUNT, 0));
				}
			});
			bm.sendBroadcast(intent);

			// On click, open the app to the conversation activity.
			final Intent clickIntent = new Intent(context, ConversationActivity.class);
			final PendingIntent pendingIntent = PendingIntent.getActivity(context, 0, clickIntent, 0);
			views.setOnClickPendingIntent(R.id.appwidget_icon, pendingIntent);

			appWidgetManager.updateAppWidget(appWidgetId, views);
		}
	}


	@Override
	public void onEnabled(final Context context) {
		// First widget is created
	}

	@Override
	public void onDisabled(final Context context) {
		// Last widget is disabled
	}

	private static void updateAppWidgetText(final Context context,
	                                        final AppWidgetManager appWidgetManager,
	                                        final int appWidgetId,
	                                        final RemoteViews views,
	                                        final int newMessages) {

		final CharSequence widgetText = context.getString(R.string.x_new_messages, newMessages);
		views.setTextViewText(R.id.appwidget_count, widgetText);

		appWidgetManager.updateAppWidget(appWidgetId, views);
	}
}


