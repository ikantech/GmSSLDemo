package com.ftsafe.chuangxin.myapplication;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.support.annotation.NonNull;
import android.text.TextUtils;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;

/**
 * Created by chuangxin on 2017/9/11.
 */

public class InputDialog extends Dialog {

    private String text;
    private int result;

    private Handler mHandler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            throw new RuntimeException();
        }
    };

    public InputDialog(@NonNull Context context) {
        super(context);
        getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        setContentView(R.layout.dialog_input);
        setCanceledOnTouchOutside(false);
        WindowManager.LayoutParams lp = getWindow().getAttributes();
        lp.width = WindowManager.LayoutParams.MATCH_PARENT;
        getWindow().setAttributes(lp);
        Button btn_ok = (Button) findViewById(R.id.dialog_btn_ok);
        btn_ok.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                text = getEditText();
                Message m = mHandler.obtainMessage();
                mHandler.sendMessage(m);
                dismiss();
            }
        });

        Button btn_cancle = (Button) findViewById(R.id.dialog_btn_cancle);
        btn_cancle.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                result = 0;
                text = null;
                Message m = mHandler.obtainMessage();
                mHandler.sendMessage(m);
                dismiss();
            }
        });

    }

    public String getText() {
        return text;
    }

    private String getEditText() {
        EditText editText = (EditText) findViewById(R.id.dialog_et_input);
        String msg = editText.getText().toString();
        result = 2;
        if (TextUtils.isEmpty(msg)) {
            result = 1;
            msg = "12345678";
        }
        return msg;
    }

    public int showDialog() {
        super.show();
        try {
            Looper.getMainLooper().loop();
        } catch (RuntimeException e2) {
        }
        return result;
    }

}
