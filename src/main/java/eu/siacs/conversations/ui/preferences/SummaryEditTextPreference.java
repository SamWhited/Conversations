package eu.siacs.conversations.ui.preferences;

import android.content.Context;
import android.preference.EditTextPreference;
import android.text.TextUtils;
import android.util.AttributeSet;

public class SummaryEditTextPreference extends EditTextPreference {
	public SummaryEditTextPreference(final Context context, final AttributeSet attrs, final int defStyle) {
		super(context, attrs, defStyle);
	}

	public SummaryEditTextPreference(final Context context, final AttributeSet attrs) {
		super(context, attrs);
	}

	public SummaryEditTextPreference(final Context context) {
		super(context);
	}

	/**
	 * getSummary returns the value of the {@link android.widget.EditText} if set, or the original summary otherwise.
	 *
	 * @return The preference value or summary
	 */
	@Override
	public CharSequence getSummary() {
		final String text = getText();
		if (TextUtils.isEmpty(text)) {
			return super.getSummary();
		} else {
			return text;
		}
	}

}
