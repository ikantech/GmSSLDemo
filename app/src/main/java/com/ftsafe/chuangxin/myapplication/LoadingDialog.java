package com.ftsafe.chuangxin.myapplication;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.support.annotation.NonNull;
import android.widget.TextView;

/**
 * Created by star on 2017/9/6.
 */

public class LoadingDialog extends Dialog {
    public LoadingDialog(@NonNull Context context) {
        super(context);
        getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        setContentView(R.layout.dialog_loading);
        setCanceledOnTouchOutside(false);
    }

    public void setText(String text){
        TextView textView = (TextView) findViewById(R.id.loading_tv_text);
        textView.setText(text);
    }

}
