package com.ftsafe.chuangxin.myapplication;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @BindView(R.id.show)
    TextView mShow;

    private InputDialog mDialog;

    private String plain;
    private String b64SignMsg;
    private String b64SM2SignMsg;
    private String b64SM2EncMsg;
    private String b64SM4EncMsg;
    private String b64AESEncMsg;
    private String key = "1824891575612348";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);
        mDialog = new InputDialog(this);
        genSM2KeyPairs();
    }

    @OnClick({R.id.btn1, R.id.btn2, R.id.btn3, R.id.btn5, R.id.btn7, R.id.btn9})
    public void onViewClicked(View view) {
        int result = mDialog.showDialog();
        StringBuffer sb = new StringBuffer();
        if (result == 1)
            Toast.makeText(this, "没有设置要加密的内容，使用默认内容 123456789", Toast.LENGTH_SHORT).show();
        if (result == 0)
            return;
        plain = mDialog.getText();
        byte[] encMsg;
        switch (view.getId()) {
            case R.id.btn1:
                encMsg = sha1(plain.getBytes(), plain.getBytes().length);
                sb.delete(0, sb.length());
                sb.append("原文 ： ").append(plain).append("\n\n")
                        .append("原文摘要 : ").append(Hex.byte2HexStr(encMsg)).append("\n\n");
                mShow.setText(sb);
                break;
            case R.id.btn2:
                encMsg = sm3(plain.getBytes(), plain.getBytes().length);
                sb.delete(0, sb.length());
                sb.append("原文 ： ").append(plain).append("\n\n")
                        .append("原文摘要 : ").append(Hex.byte2HexStr(encMsg)).append("\n\n");
                mShow.setText(sb);
                break;
            case R.id.btn3:
                encMsg = sm4Enc(plain.getBytes(), plain.getBytes().length, key.getBytes());
                b64SM4EncMsg = Base64.encodeToString(encMsg, Base64.DEFAULT);
                b64SM4EncMsg.replace("\n", "");
                sb.delete(0, sb.length());
                sb.append("key : ").append(key).append("\n\n")
                        .append("原文 ： ").append(plain).append("\n\n")
                        .append("加密结果 : ").append(b64SM4EncMsg).append("\n\n");
                mShow.setText(sb);
                break;
            case R.id.btn5:
                encMsg = sm2Enc(plain.getBytes(), plain.getBytes().length);
                b64SM2EncMsg = Base64.encodeToString(encMsg, Base64.DEFAULT);
                sb.delete(0, sb.length());
                sb.append("原文 ： ").append(plain).append("\n\n")
                        .append("密文 ： ").append(b64SM2EncMsg).append("\n\n");
                mShow.setText(sb);
                break;
            case R.id.btn7:
                encMsg = sm2Sign(plain.getBytes(), plain.getBytes().length);
                b64SM2SignMsg = Base64.encodeToString(encMsg, Base64.DEFAULT);
                b64SM2SignMsg.replace("\r", "");
                sb.delete(0, sb.length());
                sb.append("原文 ： ").append(plain).append("\n\n")
                        .append("签名 ： ").append(b64SM2SignMsg).append("\n\n");
                mShow.setText(sb);
                break;
            case R.id.btn9:
                encMsg = aesEnc(plain.getBytes(), plain.getBytes().length, key.getBytes());
                b64AESEncMsg = Base64.encodeToString(encMsg, Base64.DEFAULT);
                b64AESEncMsg.replace("\n", "");
                sb.delete(0, sb.length());
                sb.append("key : ").append(key).append("\n\n")
                        .append("原文 ： ").append(plain).append("\n\n")
                        .append("加密结果 : ").append(b64AESEncMsg).append("\n\n");
                mShow.setText(sb);
                break;
        }
    }

    @OnClick({R.id.btn4, R.id.btn6, R.id.btn8, R.id.btn10, R.id.btn12, R.id.btn14})
    public void onViewClicked2(View view) {
        StringBuffer sb = new StringBuffer();
        byte encMsg[];
        switch (view.getId()) {
            case R.id.btn4:
                encMsg = sm4Dec(Base64.decode(b64SM4EncMsg, Base64.DEFAULT), Base64.decode(b64SM4EncMsg, Base64.DEFAULT).length, key.getBytes());
                sb.delete(0, sb.length());
                sb.append("key : ").append(key).append("\n\n")
                        .append("密文 ： ").append(b64SM4EncMsg).append("\n\n")
                        .append("解密原文 : ").append(new String(encMsg)).append("\n\n");
                mShow.setText(sb);
                break;
            case R.id.btn6:
                encMsg = sm2Dec(Base64.decode(b64SM2EncMsg, Base64.DEFAULT), Base64.decode(b64SM2EncMsg, Base64.DEFAULT).length);
                sb.delete(0, sb.length());
                sb.append("密文 ： ").append(b64SM2EncMsg).append("\n\n")
                        .append("解密原文 : ").append(new String(encMsg)).append("\n\n");
                mShow.setText(sb);
                break;
            case R.id.btn8:
                String result = null;
                int ret = sm2Verify(plain.getBytes(), plain.getBytes().length, Base64.decode(b64SM2SignMsg, Base64.DEFAULT), Base64.decode(b64SM2SignMsg, Base64.DEFAULT).length);
                if (ret == 0)
                    result = "驗證失敗！";
                if (ret == 1)
                    result = "驗證通過！";
                sb.append("原文 ： ").append(plain).append("\n\n")
                        .append("簽名 : ").append(b64SM2SignMsg).append("\n\n")
                        .append("騐簽結果 ： ").append(result).append("\n\n");
                mShow.setText(sb);
                break;
            case R.id.btn10:
                encMsg = aesDec(Base64.decode(b64AESEncMsg, Base64.DEFAULT), Base64.decode(b64AESEncMsg, Base64.DEFAULT).length, key.getBytes());
                sb.delete(0, sb.length());
                sb.append("key : ").append(key).append("\n\n")
                        .append("密文 ： ").append(b64AESEncMsg).append("\n\n")
                        .append("解密原文 : ").append(new String(encMsg)).append("\n\n");
                mShow.setText(sb);
                break;
            case R.id.btn12:
                break;
            case R.id.btn14:
                break;
        }
    }


    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */

    public native byte[] sha1(byte in[], int length);

    public native byte[] sm3(byte in[], int length);

    public native byte[] aesEnc(byte in[], int length, byte key[]);

    public native byte[] aesDec(byte in[], int length, byte key[]);

    public native byte[] sm4Enc(byte in[], int length, byte key[]);

    public native byte[] sm4Dec(byte in[], int length, byte key[]);

    public native byte[] sm2Enc(byte in[], int length);

    public native byte[] sm2Dec(byte in[], int length);

    public native byte[] sm2Sign(byte in[], int length);

    public native int sm2Verify(byte in[], int length, byte sign[], int signLen);

    public native int genSM2KeyPairs();
}
