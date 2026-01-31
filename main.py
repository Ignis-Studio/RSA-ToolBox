import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import base64 
import os
from cryp_utils import generate_rsa_keys, sign_message, verify_signature, check_key_validity


class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA ToolBox")
        self.root.geometry("650x800") 

        self.create_widgets()

    def create_widgets(self):
        # === 1. 密钥生成区域 ===
        gen_frame = ttk.LabelFrame(self.root, text="1. 生成 RSA 密钥对")
        gen_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(gen_frame, text="密钥长度 (Bits):").grid(row=0, column=0, padx=5, pady=5)
        self.bits_entry = ttk.Entry(gen_frame, width=10)
        self.bits_entry.insert(0, "2048")
        self.bits_entry.grid(row=0, column=1, sticky="w")

        ttk.Button(gen_frame, text="生成密钥", command=self.do_generate_keys).grid(row=0, column=2, padx=10)

        # === 2. 签名/加密区域 ===
        sign_frame = ttk.LabelFrame(self.root, text="2. 消息签名 (Sign Message)")
        sign_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(sign_frame, text="私钥 (Private Key):").pack(anchor="w", padx=5)
        self.sign_priv_key_text = scrolledtext.ScrolledText(sign_frame, height=4, width=70)
        self.sign_priv_key_text.pack(padx=5, pady=2)

        ttk.Label(sign_frame, text="消息 (Message):").pack(anchor="w", padx=5)
        self.sign_msg_entry = ttk.Entry(sign_frame, width=70)
        self.sign_msg_entry.pack(padx=5, pady=2)

        ttk.Button(sign_frame, text="执行签名", command=self.do_sign).pack(pady=5)

        ttk.Label(sign_frame, text="生成的签名 (Base64 Output):").pack(anchor="w", padx=5)
        self.signature_output = scrolledtext.ScrolledText(sign_frame, height=4, width=70)
        self.signature_output.pack(padx=5, pady=2)

        # === 3. 验签区域 ===
        verify_frame = ttk.LabelFrame(self.root, text="3. 验证签名 (Verify Signature)")
        verify_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(verify_frame, text="公钥 (Public Key):").pack(anchor="w", padx=5)
        self.verify_pub_key_text = scrolledtext.ScrolledText(verify_frame, height=4, width=70)
        self.verify_pub_key_text.pack(padx=5, pady=2)

        ttk.Label(verify_frame, text="原始消息 (Message):").pack(anchor="w", padx=5)
        self.verify_msg_entry = ttk.Entry(verify_frame, width=70)
        self.verify_msg_entry.pack(padx=5, pady=2)

        ttk.Label(verify_frame, text="待验证签名 (Base64 Input):").pack(anchor="w", padx=5)
        self.verify_sig_text = scrolledtext.ScrolledText(verify_frame, height=4, width=70)
        self.verify_sig_text.pack(padx=5, pady=2)

        ttk.Button(verify_frame, text="验证签名", command=self.do_verify).pack(pady=5)

        # === 4. 密钥有效性检查 ===
        check_frame = ttk.LabelFrame(self.root, text="4. 工具：检查密钥有效性")
        check_frame.pack(fill="x", padx=10, pady=5) 
        
        # 顶部操作栏（标签 + 按钮）
        top_bar = ttk.Frame(check_frame)
        top_bar.pack(padx=5, pady=5)
        
        ttk.Label(top_bar, text="粘贴密钥到下方:").pack(side="left")
        ttk.Button(top_bar, text="检查有效性", command=self.do_check_validity).pack(side="right")

        # 底部多行文本框
        self.check_key_text = scrolledtext.ScrolledText(check_frame, height=5, width=70)
        self.check_key_text.pack(padx=5, pady=5)

    # --- 逻辑处理函数 ---

    def do_generate_keys(self):
        try:
            bits = int(self.bits_entry.get())
            priv_key, pub_key = generate_rsa_keys(bits=bits)
            
            if priv_key is None:
                messagebox.showerror("错误", "密钥生成返回为空，请检查控制台错误信息。")
                return

            # 如果返回的是 bytes，需要 decode 成 string 显示
            if isinstance(priv_key, bytes):
                priv_key = priv_key.decode('utf-8')
            if isinstance(pub_key, bytes):
                pub_key = pub_key.decode('utf-8')

            # 填充 UI
            self.sign_priv_key_text.delete('1.0', tk.END)
            self.sign_priv_key_text.insert(tk.END, priv_key)
            
            self.verify_pub_key_text.delete('1.0', tk.END)
            self.verify_pub_key_text.insert(tk.END, pub_key)
            
            messagebox.showinfo("成功", f"已生成 {bits} 位 RSA 密钥对！")
            
        except ValueError:
            messagebox.showerror("错误", "Bits 必须是整数")

    def do_sign(self):
        try:
            priv_key = self.sign_priv_key_text.get('1.0', tk.END).strip()
            msg = self.sign_msg_entry.get()
            
            if not priv_key or not msg:
                messagebox.showwarning("警告", "私钥和消息不能为空")
                return

            # 调用后端签名函数（返回 bytes）
            raw_signature = sign_message(priv_key, msg)
            
            if raw_signature is None:
                messagebox.showerror("签名失败", "后端返回 None，请检查私钥格式是否正确。")
                return

            # 【关键修改】将 bytes 转为 Base64 字符串用于显示
            b64_signature = base64.b64encode(raw_signature).decode('utf-8')
            
            # 显示签名
            self.signature_output.delete('1.0', tk.END)
            self.signature_output.insert(tk.END, b64_signature)
            
            # 自动复制到验签区方便测试
            self.verify_sig_text.delete('1.0', tk.END)
            self.verify_sig_text.insert(tk.END, b64_signature)
            self.verify_msg_entry.delete(0, tk.END)
            self.verify_msg_entry.insert(0, msg)
            
        except Exception as e:
            messagebox.showerror("程序错误", str(e))

    def do_verify(self):
        try:
            pub_key = self.verify_pub_key_text.get('1.0', tk.END).strip()
            msg = self.verify_msg_entry.get()
            b64_sig = self.verify_sig_text.get('1.0', tk.END).strip()

            if not pub_key or not msg or not b64_sig:
                messagebox.showwarning("警告", "公钥、消息和签名都不能为空")
                return

            # 【关键修改】将 Base64 字符串还原为 bytes 传给后端
            try:
                raw_sig = base64.b64decode(b64_sig)
            except Exception:
                messagebox.showerror("格式错误", "签名不是有效的 Base64 格式！")
                return

            # 调用验签
            is_valid = verify_signature(pub_key, msg, raw_sig)
            
            if is_valid:
                messagebox.showinfo("验证结果", "✅ 签名有效 (Valid)\n数据未被篡改，且来源可信。")
            else:
                messagebox.showerror("验证结果", "❌ 签名无效 (Invalid)\n可能是消息被篡改、公钥不匹配或签名数据损坏。")
                
        except Exception as e:
            messagebox.showerror("验证过程出错", str(e))

    def do_check_validity(self):
        key_data = self.check_key_text.get("1.0", tk.END).strip()
        if not key_data:
            messagebox.showwarning("提示", "请输入密钥内容")
            return
        
        # 为了兼容 bytes/str 输入，这里尝试都做一下处理
        if isinstance(key_data, str):
            key_data = key_data.encode('utf-8')

        is_valid = check_key_validity(key_data)
        if is_valid:
            messagebox.showinfo("检查结果", "✅ 密钥格式有效")
        else:
            messagebox.showwarning("检查结果", "⚠️ 密钥格式无效")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()