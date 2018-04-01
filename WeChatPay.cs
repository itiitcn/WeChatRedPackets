using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using System.Web.Script.Serialization;

namespace WeChat.Demo
{
    public class WeChatPayController : Controller
    {
        //跳转微信登录页面
        public ActionResult Index()
        {
            string appid = "";//服务号appid
            string redirect_uri = "";// 微信重定向域名(填写程序域名, 例如: www.xxxx.com)
            string control = ""; //程序控制器名,例如: WeChatPay
            string action = "";//程序Action名,例如: RedirectWeChat
            ViewBag.url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid="
            + appid
            + "&redirect_uri=http%3A%2F%2F" + redirect_uri
            + "%2F" + control
            + "%2F" + action
            + "&response_type=code&scope=snsapi_userinfo&state=STATE#wechat_redirect";
            return View();
        }

        //获取accesstoken(访问微信接口需要)
        public static string accesstoken(string WeChatWxAppId, string WeChatWxAppSecret)
        {
            string strJson = HttpRequestUtil.RequestUrl(
                string.Format(
                "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={0}&secret={1}",
                WeChatWxAppId, WeChatWxAppSecret
                )
            );
            if (strJson.IndexOf("errcode") == -1)
            {
                return GetJsonValue(strJson, "access_token");
            }
            else
            {
                return "";
            }
        }
        //解析json
        public static string GetJsonValue(string jsonStr, string key)
        {
            string result = string.Empty;
            if (!string.IsNullOrEmpty(jsonStr))
            {
                key = "\"" + key.Trim('"') + "\"";
                int index = jsonStr.IndexOf(key) + key.Length + 1;
                if (index > key.Length + 1)
                {
                    //先截逗号，若是最后一个，截“｝”号，取最小值
                    int end = jsonStr.IndexOf(',', index);
                    if (end == -1)
                    {
                        end = jsonStr.IndexOf('}', index);
                    }
                    result = jsonStr.Substring(index, end - index);
                    result = result.Trim(new char[] { '"', ' ', '\'' }); //过滤引号或空格
                }
            }
            return result;
        }

        //请求url
        public static string RequestUrl(string url, string method = "post")
        {
            // 设置参数
            HttpWebRequest request = WebRequest.Create(url) as HttpWebRequest;
            CookieContainer cookieContainer = new CookieContainer();
            request.CookieContainer = cookieContainer;
            request.AllowAutoRedirect = true;
            request.Method = method;
            request.ContentType = "text/html";
            request.Headers.Add("charset", "utf-8");
            //发送请求并获取相应回应数据
            HttpWebResponse response = request.GetResponse() as HttpWebResponse;
            //直到request.GetResponse()程序才开始向目标网页发送Post请求
            Stream responseStream = response.GetResponseStream();
            StreamReader sr = new StreamReader(responseStream, Encoding.UTF8);
            //返回结果网页（html）代码
            string content = sr.ReadToEnd();
            return content;
        }
        //接收微信返回code
        //接收微信数据获取用户信息
        public ActionResult RedirectWeChat(string code, string state)
        {
            if (string.IsNullOrEmpty(code))
            {
                return Content("您拒绝了授权！");
            }
            string access_token = accesstoken(微信AppId, 微信AppSecret);
            string st = "https://api.weixin.qq.com/sns/oauth2/access_token?appid="
            + 微信AppId + "&secret=" + 微信AppSecret + "&code="
            + code + "&grant_type=authorization_code";

            string data = RequestUrl(st);
            //拿到用户openid
            string openid = GetJsonValue(data, "openid");
            //获取用户其他信息
            string url = "https://api.weixin.qq.com/cgi-bin/user/info?access_token="
             + access_token + "&openid=" + openid + "&lang=zh_CN";
            data = RequestUrl(url);
            string subscribe = GetJsonValue(data, "subscribe");
            if (subscribe == "0")
            {
                ///未关注
                return RedirectToAction("");
            }

            return RedirectToAction("");
        }

        //发送红包Action
        public ActionResult HB()
        {
            string openid = "";//用户openid
            string url = "https://api.mch.weixin.qq.com/mmpaymkttransfers/sendredpack";
            //商户订单号 组成：mch_id+yyyymmdd+10位一天内不能重复的数字。 
            string orderNo = 商户号 + DateTime.Now.ToString("yyyymmdd") + "随机10位数字";
            //支付密钥(在商户平台设置32为字符串) 
            string Code = "";//32为随机字符串; 
            string key = "key=" + "";
            Dictionary<string, string> data = new Dictionary<string, string>();
            data.Add("act_name", "");//活动名称 
            data.Add("client_ip", "192.168.1.1");//Ip地址 
            data.Add("mch_billno", orderNo);//商户订单号 组成：mch_id+yyyymmdd+10位一天内不能重复的数字。 
            data.Add("mch_id", "");//商户号 
            data.Add("nonce_str", Code);//随机字符串 
            data.Add("re_openid", openid);//用户openid 
            data.Add("remark", "");//备注 
            data.Add("send_name", "");//商户名称 
            data.Add("total_amount", "100");//付款金额 单位分 
            data.Add("total_num", "1");//红包发放总人数 
            data.Add("wishing", "恭喜发财");//红包祝福语 
            data.Add("wxappid", "");//公众账号appid 
            string xml = GetXML(data, key);//签名+拼接xml 
            string str = PostWebRequests(url, xml);//微信返回xml err_code=SUCCESS 就是成功
            return View("");
        }

        //发送红包(MD5签名+拼接XML)
        public static string GetXML(Dictionary<string, string> data, string paykey)
        {
            string retStr;
            MD5CryptoServiceProvider m5 = new MD5CryptoServiceProvider();

            var data1 = from d in data orderby d.Key select d;
            string data2 = "";
            string XML = "<xml>";
            foreach (var item in data1)
            {
                //空值不参与签名
                if (item.Value + "" != "")
                {
                    data2 += item.Key + "=" + item.Value + "&";
                }
                XML += "<" + item.Key + ">" + item.Value + "" + "</" + item.Key + ">";
            }

            data2 += paykey;
            //创建md5对象
            byte[] inputBye;
            byte[] outputBye;

            //使用GB2312编码方式把字符串转化为字节数组．
            try
            {
                inputBye = Encoding.UTF8.GetBytes(data2);
            }
            catch
            {
                inputBye = Encoding.GetEncoding("GB2312").GetBytes(data2);
            }
            outputBye = m5.ComputeHash(inputBye);

            retStr = System.BitConverter.ToString(outputBye);
            retStr = retStr.Replace("-", "").ToUpper();
            XML += "<sign>" + retStr + "</sign>";//签名
            XML += "</xml>";
            return XML;
        }

        //发送红包请求Post方法
        public static string PostWebRequests(string postUrl, string menuInfo)
        {
            string returnValue = string.Empty;
            try
            {
                Encoding encoding = Encoding.UTF8;
                byte[] bytes = encoding.GetBytes(menuInfo);
                string cert = @"E:\cdcert\apiclient_cert.p12";//支付证书路径
                string password = "1212121";//支付证书密码

                ServicePointManager.ServerCertificateValidationCallback
                        = new RemoteCertificateValidationCallback(CheckValidationResult);
                X509Certificate cer
                        = new X509Certificate(cert, password, X509KeyStorageFlags.MachineKeySet);
                HttpWebRequest webrequest = (HttpWebRequest)HttpWebRequest.Create(postUrl);
                webrequest.ClientCertificates.Add(cer);
                webrequest.Method = "post";
                webrequest.ContentLength = bytes.Length;
                webrequest.GetRequestStream().Write(bytes, 0, bytes.Length);
                HttpWebResponse webreponse = (HttpWebResponse)webrequest.GetResponse();
                Stream stream = webreponse.GetResponseStream();
                string resp = string.Empty;
                using (StreamReader reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd();
                }

            }
            catch (Exception ex)
            {
                return "";
            }
        }
    }
}
