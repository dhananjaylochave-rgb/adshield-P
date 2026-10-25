package app.dj.adshield;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import java.util.List;
import java.util.Locale;

/** Single-screen UI built in code (no layouts, no libraries). */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 1000);
        }
    };

    private TextView status;
    private TextView stats;
    private TextView warning;
    private TextView recent;
    private Button toggle;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Shared.loadPrefs(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(28), dp(20), dp(20));

        TextView title = text("AdShield", 28, true);
        root.addView(title);
        root.addView(text("DNS ad blocker. The block list is built into this app.", 14, false));

        status = text("", 22, true);
        status.setPadding(0, dp(24), 0, dp(8));
        root.addView(status);

        toggle = new Button(this);
        toggle.setOnClickListener(v -> onToggle());
        root.addView(toggle, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        warning = text("Strict Private DNS is ON in system settings, so Android bypasses AdShield. "
                + "Set Settings > Network > Private DNS to Off or Automatic.", 14, false);
        warning.setTextColor(Color.parseColor("#FF8A65"));
        warning.setPadding(0, dp(12), 0, 0);
        root.addView(warning);

        stats = text("", 16, false);
        stats.setPadding(0, dp(16), 0, dp(8));
        root.addView(stats);

        TextView upLabel = text("Forward allowed lookups to:", 14, false);
        upLabel.setPadding(0, dp(8), 0, 0);
        root.addView(upLabel);
        Spinner spinner = new Spinner(this);
        spinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, Shared.UPSTREAM_NAMES));
        spinner.setSelection(Shared.upstreamIndex);
        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (position == Shared.upstreamIndex) return;
                Shared.upstreamIndex = position;   // used on the very next lookup, no restart needed
                prefs().edit().putInt(Shared.KEY_UPSTREAM, position).apply();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
        root.addView(spinner);

        Button allow = new Button(this);
        allow.setText("Allow list (unblock a site)");
        allow.setOnClickListener(v -> showAllowDialog());
        root.addView(allow);

        TextView recentTitle = text("Recently blocked (kept in memory only)", 14, true);
        recentTitle.setPadding(0, dp(16), 0, dp(4));
        root.addView(recentTitle);
        recent = text("", 12, false);
        recent.setTypeface(Typeface.MONOSPACE);
        root.addView(recent);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(tick);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(tick);
        super.onPause();
    }

    private void onToggle() {
        if (Shared.running) {
            Intent stop = new Intent(this, AdBlockVpnService.class).setAction(AdBlockVpnService.ACTION_STOP);
            startService(stop);
            handler.postDelayed(this::refresh, 400);
            return;
        }
        Intent prepare = VpnService.prepare(this);   // null when permission was already granted
        if (prepare != null) {
            startActivityForResult(prepare, REQ_VPN);
        } else {
            startVpn();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) startVpn();
    }

    private void startVpn() {
        Shared.resetCounters();
        startService(new Intent(this, AdBlockVpnService.class));
        handler.postDelayed(this::refresh, 600);
    }

    private void refresh() {
        boolean on = Shared.running;
        status.setText(on ? "Protection ON" : "Protection OFF");
        status.setTextColor(Color.parseColor(on ? "#66BB6A" : "#EF5350"));
        toggle.setText(on ? "Turn off" : "Turn on");

        long t = Shared.total.get();
        long b = Shared.blocked.get();
        String pct = t == 0 ? "-" : String.format(Locale.US, "%.0f%%", 100.0 * b / t);
        stats.setText(String.format(Locale.US,
                "Blocked %d of %d lookups (%s)\nList: %s domains",
                b, t, pct,
                Shared.blocklistSize > 0 ? String.format(Locale.US, "%,d", Shared.blocklistSize) : "loads when started"));

        String mode = Settings.Global.getString(getContentResolver(), "private_dns_mode");
        warning.setVisibility("hostname".equals(mode) ? View.VISIBLE : View.GONE);

        List<String> r = Shared.recentBlocked();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(r.size(), 25); i++) sb.append(r.get(i)).append('\n');
        recent.setText(sb.length() == 0 ? "(nothing yet)" : sb.toString());
    }

    private void showAllowDialog() {
        final EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_VARIATION_URI);
        input.setMinLines(5);
        input.setGravity(Gravity.TOP | Gravity.START);
        input.setText(prefs().getString(Shared.KEY_ALLOW, ""));
        new AlertDialog.Builder(this)
                .setTitle("Never block these domains")
                .setMessage("One per line. A domain also covers its subdomains. Lines starting with # are notes.")
                .setView(input)
                .setPositiveButton("Save", (d, w) -> {
                    String raw = input.getText().toString();
                    prefs().edit().putString(Shared.KEY_ALLOW, raw).apply();
                    Shared.allow = Blocklist.parseList(raw);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(Shared.PREFS, Context.MODE_PRIVATE);
    }

    private TextView text(String s, int sp, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private int dp(int v) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                getResources().getDisplayMetrics()));
    }
}
