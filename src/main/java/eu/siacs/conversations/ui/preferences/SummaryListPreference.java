package eu.siacs.conversations.ui.preferences;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.preference.ListPreference;
import android.text.TextUtils;
import android.util.AttributeSet;

public class SummaryListPreference extends ListPreference {
	@TargetApi(Build.VERSION_CODES.LOLLIPOP)
	public SummaryListPreference(final Context context,
			final AttributeSet attrs,
			final int defStyleAttr,
			final int defStyleRes) {
		super(context, attrs, defStyleAttr, defStyleRes);
	}

	@TargetApi(Build.VERSION_CODES.LOLLIPOP)
	public SummaryListPreference(final Context context, final AttributeSet attrs, final int defStyleAttr) {
		super(context, attrs, defStyleAttr);
	}

	public SummaryListPreference(final Context context, final AttributeSet attrs) {
		super(context, attrs);
	}

	public SummaryListPreference(final Context context) {
		super(context);
	}

	@Override
	public CharSequence getSummary() {
		final CharSequence text = this.getEntry();
		if (TextUtils.isEmpty(text)) {
			return super.getSummary();
		} else {
			return text;
		}
	}
}
