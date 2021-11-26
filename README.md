# test

### API की अनुकूलता {#api}
अधिकांश कुबेरनेट्स API Windows के लिए कैसे काम करते हैं, इसमें कोई अंतर नहीं है। {OS और कंटेनर रनटाइम में अंतर के कारण अलग-अलग सूक्ष्मताएं आती हैं रनटाइम}। कुछ स्थितियों में कार्यभार संसाधनों पर कुछ गुण डिज़ाइन किए गए थे इस धारणा के तहत कि उन्हें लिनक्स पर लागू किया जाएगा, और Windows पर चलने में विफल रहेगा।

उच्च स्तर पर, ये OS भिन्न अवधारणाएँ हैं:
* पहचान - लिनक्स यूजरआईडी (UID) और ग्रुपआईडी (GID) का उपयोग करता है जो पूर्णांक प्रकारों के रूप में दर्शाए जाते हैं। उपयोगकर्ता और समूह के नाम विहित नहीं हैं - वे `/etc/groups` . में सिर्फ एक उपनाम हैं या `/etc/passwd` यूआईडी जीआईडी ​​पर वापस जाएं। Windows एक बड़े बाइनरी का उपयोग करता है [सुरक्षा पहचानकर्ता](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) (SID) जो Windows सिक्योरिटी एक्सेस मैनेजर (SAM) डेटाबेस में स्टोर होता है। इस डेटाबेस को मेज़बान के बीच साझा नहीं किया जाता है।
* फ़ाइल अनुमतियां - Windows (SIDs) के आधार पर एक्सेस कंट्रोल सूची का उपयोग करता है, जबकि POSIX सिस्टम जैसे Linux ऑब्जेक्ट अनुमतियों,  _optional_ अभिगम नियंत्रण सूचिय और UID+GID के आधार पर बिटमास्क का उपयोग करता है।
* फ़ाइल पथ - सम्मेलन के आधार पर Windows पर `/` के बजाय `\` का उपयोग करना होता है। गो I पुस्तकालय आमतौर पर दोनों को स्वीकार करते हैं और बस इसे काम करते हैं, लेकिन जब आप पथ या कमांड लाइन जो एक कंटेनर के अंदर व्याख्या की गई है, `\` की आवश्यकता हो सकती है। 
* सिग्नल - Windows इंटरएक्टिव ऐप टर्मिनेशन को अलग तरह से हैंडल करते हैं, और इनमें से एक या अधिक को लागू कर सकते हैं:
    * UI थ्रेड `WM_CLOSE` सहित अच्छी तरह से परिभाषित संदेशों को संभालता है।
    * कंसोल ऐप्स कंट्रोल हैंडलर का उपयोग करके Ctrl-C या Ctrl-break को हैंडल करते हैं।
    * सेवाएँ एक सर्विस कण्ट्रोल हैंडलर हैंडलर फ़ंक्शन पंजीकृत करती हैं जो स्वीकार कर सकता है`SERVICE_CONTROL_STOP` नियंत्रण कोड।

कंटेनर निकास कोड उसी परंपरा का पालन करते हैं जहां 0 सफलता है, और गैर-शून्य विफलता है। विशिष्ट त्रुटि कोड Windows और लिनक्स में भिन्न हो सकते हैं। हालाँकि, निकास कोड कुबेरनेट्स घटकों (क्यूबलेट, क्यूब-प्रॉक्सी) से पारित अपरिवर्तित हैं।

#### कंटेनर विनिर्देशों के लिए फ़ील्ड संगतता {#compatibility-v1-pod-spec-containers}

निम्नलिखित सूची में Windows और लिनक्स के बीच पॉड कंटेनर विनिर्देशों का अंतर बताया गया है:

* Windows कंटेनर में HUGO पृष्ठ लागू नहीं होते हैं रनटाइम, और उपलब्ध नहीं हैं। उन्हें आवश्यकता है [एक उपयोगकर्ता के विशेषाधिकार पर जोर देना](https://docs.microsoft.com/en-us/windows/desktop/Memory/large-page-support) जो की   कंटेनरों के लिए विन्यास योग्य नहीं हो।
* `requests.cpu` और `requests.memory` - से अनुरोध घटाए जाते हैं नोड उपलब्ध संसाधनों से, इसलिए उनका उपयोग अधिक प्रावधान से बचने के लिए किया जा सकता है। हालाँकि, उनका उपयोग एक अत्यधिक प्रावधान नोड में संसाधनों की गारंटी के लिए नहीं किया जा सकता है।  उन्हें सभी कंटेनरों पर सर्वोत्तम अभ्यास के रूप में लागू किया जाना चाहिए यदि ऑपरेटर पूरी तरह से अधिक प्रावधान से बचना चाहता है।
* `securityContext.allowPrivilegeEscalation` -Windows पर संभव नहीं है; क्षमताओं में से कोई भी जुड़ा हुआ नहीं है
* `securityContext.capabilities` -Windows पर पॉज़िक्स क्षमताओं को लागू नहीं किया गया है
* `securityContext.privileged`-Windows विशेषाधिकार प्राप्त कंटेनरों का समर्थन नहीं करता
* `securityContext.procMount` -Windows में `/ proc` फाइल सिस्टम नहीं है
* `securityContext.readOnlyRootFilesystem` -Windows पर संभव नहीं है; रजिस्ट्री के लिए लेखन पहुंच आवश्यक है
* `securityContext.runAsGroup` -Windows पर संभव नहीं है क्योंकि कोई GID समर्थन नहीं है
* `securityContext.runAsNonRoot` - यह सेटिंग कंटेनर को कंटेनरएडमिनिस्ट्रेटर के रूप में चलने से रोकेगी जो Windows पर रूट उपयोगकर्ता के निकटतम समकक्ष है
* `securityContext.runAsUser` -[`runAsUserName`](/docs/tasks/configure-pod-container/configure-runasusername) का उपयोग करें बजाय
* `securityContext.seLinuxOptions` -Windows पर संभव नहीं है क्योंकि SELinux Linux-विशिष्ट है
* `terminationMessagePath` -इसकी कुछ सीमाएँ हैं कि Windows एकल फ़ाइलों की मैपिंग का समर्थन नहीं करता है। NS डिफ़ॉल्ट मान `/dev/termination-log` जो काम करता है क्योंकि यह डिफ़ॉल्ट रूप से Windows पर मौजूद नहीं है।

#### पॉड विनिर्देशों के लिए फ़ील्ड संगतता {#compatibility-v1-pod}

Windows़ और लिनक्स के बीच पॉड विनिर्देशों के काम करने के तरीके के बीच निम्न सूची दस्तावेज़ अंतर:

* `hostIPC` और `hostpid` - Windows पर होस्ट नेमस्पेस साझा करना संभव नहीं है
* `hostnetwork` - होस्ट नेटवर्क को साझा करने के लिए कोई Windows OS समर्थन नहीं है
* `dnsPolicy` - पॉड `dnsPolicy` को `ClusterFirstWithHostNet` पर सेट करना है Windows पर समर्थित नहीं है क्योंकि होस्ट नेटवर्किंग प्रदान नहीं की गई है। पॉड्स हमेशा एक कंटेनर नेटवर्क के साथ चलाएं।
* `podSecurityContext` (नीचे देखें)
* `shareProcessNamespace` - यह एक बीटा सुविधा है, और यह Linux नेमस्पेस पर निर्भर करती है जो Windows़ पर लागू नहीं हैं। Windows प्रक्रिया नामस्थान साझा नहीं कर सकता या कंटेनर की रूट फाइल सिस्टम। केवल नेटवर्क साझा किया जा सकता है।
* `terminationGracePeriodSeconds` - यह Windows पर डॉकर में पूरी तरह से लागू नहीं है, [गिटहब मुद्दा] (https://github.com/moby/moby/issues/25982) देखें। आज व्यवहार यह है कि ENTRYPOINT प्रक्रिया CTRL_SHUTDOWN_EVENT भेजी जाती है, तब Windows डिफ़ॉल्ट रूप से 5 सेकंड प्रतीक्षा करता है, और अंत में बंद हो जाता है सामान्य Windows शटडाउन व्यवहार का उपयोग करने वाली सभी प्रक्रियाएं। 5 दूसरा डिफ़ॉल्ट वास्तव में Windows रजिस्ट्री में है [कंटेनर के अंदर](https://github.com/moby/moby/issues/25982#issuecomment-42644183), इसलिए जब कंटेनर बनाया जाता है तो इसे ओवरराइड किया जा सकता है।
* `volumeDevice` - यह एक बीटा सुविधा है, और इसे Windows पर लागू नहीं किया गया है। Windows कच्चे ब्लॉक डिवाइस को पॉड्स में संलग्न नहीं कर सकता है।
* `volumes`
  * यदि आप 'emptyDir' वॉल्यूम को परिभाषित करते हैं, तो आप इसके वॉल्यूम स्रोत को 'memory' पर सेट नहीं कर सकते हैं।
* आप वॉल्यूम माउंट के लिए `mountPropagation` को सक्षम नहीं कर सकते क्योंकि यह Windows पर समर्थित नहीं है।


#### पॉड सुरक्षा प्रसंग के लिए फ़ील्ड संगतता {#compatibility-v1-pod-spec-containers-securitycontext}

कोई भी पॉड [`securityContext`](/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context) फ़ील्ड Windows पर काम नहीं करती है।

### नोड समस्या डिटेक्टर

नोड समस्या डिटेक्टर (देखें [नोड स्वास्थ्य की निगरानी करें](/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context)) Windows के साथ संगत नहीं है।


### कंटेनर रोकें

कुबेरनेट्स पॉड में, पहले एक बुनियादी ढांचा या "ठहराव" कंटेनर बनाया जाता है कंटेनर होस्ट करने के लिए। Linux में, cgroups और नेमस्पेस जो एक पॉड बनाते हैं अपने निरंतर अस्तित्व को बनाए रखने के लिए एक प्रक्रिया की आवश्यकता है; ठहराव प्रक्रिया प्रदान करता है यह। कंटेनर जो एक ही पॉड से संबंधित हैं, जिसमें बुनियादी ढांचा और कार्यकर्ता शामिल हैं कंटेनर, एक साझा नेटवर्क समापन बिंदु (समान IPv4 और / या IPv6 पता, समान नेटवर्क पोर्ट स्पेस)। कुबेरनेट्स वर्कर कंटेनरों को अनुमति देने के लिए पॉज़ कंटेनरों का उपयोग करता है किसी भी नेटवर्किंग कॉन्फ़िगरेशन को खोए बिना क्रैश या पुनरारंभ करना।

Kubernetes एक बहु-आर्किटेक्चर छवि रखता है जिसमें Windows के लिए समर्थन शामिल है। Kubernetes v1.22 के लिए अनुशंसित विराम छवि `k8s.gcr.io/pause:3.5` है। [स्रोत कोड](https://github.com/kubernetes/kubernetes/tree/master/build/pause) गिटहब पर उपलब्ध है।

Microsoft Linux और Windows के साथ एक अलग बहु-वास्तुकला छवि रखता है amd64 समर्थन, जिसे आप `mcr.microsoft.com/oss/kubernetes/pause:3.5` के रूप में पा सकते हैं। यह इमेज उसी स्रोत से बनाई गई है जैसे कुबेरनेट्स ने इमेज  को बनाए रखा लेकिन सभी Windows बायनेरिज़ [प्रामाणिक कोड हस्ताक्षरित](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode) Microsoft द्वारा हैं। अगर आप एक उत्पादन या उत्पादन जैसे वातावरण में तैनात करना चाहते है जिसको हस्ताक्षर की हुए बिनारिएस की ज़रूरत होती है तो कुबेरनेटेस प्रोजेक्ट माइक्रोसॉफ्ट अनुरक्षित इमेज का उपयोग करने करने की अनुशंसा करता है।

### कंटेनर रनटाइम {#container-runtime}

आपको एक {{< glossary_tooltip text="कंटेनर रनटाइम" term_id="container-runtime">}} को स्थापित करने की आवश्यकता है क्लस्टर में प्रत्येक नोड में ताकि पॉड वहां चल सकें।

निम्नलिखित कंटेनर रनटाइम Windows के साथ काम करते हैं:

{{% thirdparty-content %}}

#### cri-कन्टैनर्ड

{{< feature-state for_k8s_version="v1.20" state="stable" >}}

आप {{< glossary_tooltip term_id="containerd" text="ContainerD" >}} 1.4.0+ का उपयोग कर सकते हैं Windows चलाने वाले कुबेरनेट्स नोड्स के लिए कंटेनर रनटाइम के रूप में।

जानें कि कैसे [Windows नोड पर कंटेनरडी इंस्टॉल करें](/docs/setup/production-environment/container-runtimes/#install-containerd).

{{< note >}}
एक [ज्ञात सीमा](/docs/tasks/configure-pod-container/configure-gmsa/#gmsa-limitations) है Windows नेटवर्क शेयरों तक पहुंचने के लिए कंटेनरड के साथ जीएमएसए का उपयोग करते समय, जिसके लिए एक की आवश्यकता होती है
कर्नेल पैच।
{{< /note >}}

#### डोकर EE

{{< feature-state for_k8s_version="v1.14" state="stable" >}}

[डॉकर ईई](https://docs.mirantis.com/containers/v3.0/dockeree-products/dee-intro.html)-basic 19.03+ सभी Windows सर्वर संस्करणों के लिए कंटेनर रनटाइम के रूप में उपलब्ध है। यह लीगेसी डॉकशिम एडॉप्टर के साथ काम करता है।

अधिक जानकारी के लिए [Install Docker](https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/deploy-containers-on-server#install-docker) देखें।

## Windows OS संस्करण संगतता {#windows-os-version-support}

Windows नोड्स पर, सख्त संगतता नियम लागू होते हैं जहां होस्ट OS संस्करण होना चाहिए कंटेनर आधार छवि OS संस्करण से मेल खाता है। एक कंटेनर के साथ केवल Windows कंटेनर Windows सर्वर 2019 का ऑपरेटिंग सिस्टम पूरी तरह से समर्थित है।

कुबेरनेटेस v1.22 के लिए, Windows नोड्स (और पॉड्स) के लिए ऑपरेटिंग सिस्टम संगतता इस प्रकार है:

Windows सर्वर LTSC रिलीज
: Windows सर्वर 2019

Windows सर्वर SAC रिलीज
: Windows सर्वर संस्करण 2004, Windows सर्वर संस्करण 20H2

Kubernetes [संस्करण-तिरछा नीति](/docs/setup/release/version-skew-policy/) भी लागू होता 

## Windows नोड्स के लिए सुरक्षा {#security}

Windows पर, सीक्रेट्स के डेटा को नोड के लोकल भंडारण (लिनक्स पर tmpfs / इन-मेमोरी फाइल सिस्टम के उपयोग की तुलना में) पर स्पष्ट टेक्स्ट में लिखा जाता है।

1. सीक्रेट्स की फाइल लोकेशन को सुरक्षित करने के लिए फाइल ACLs का इस्तेमाल करें।
1. [BitLocker](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-how-to-deploy-on-windows-server) का उपयोग करके वॉल्यूम-स्तर एन्क्रिप्शन लागू करें

[RunAsUsername](/docs/tasks/configure-pod-container/configure-runasusername)Windows पॉड्स या कंटेनर्स के कंटेनर की प्रक्रियाओं को नोड डिफ़ॉल्ट उपयोगकर्ता के रूप में निष्पादित किया जा सकता है। यह मोटे तौर पर [RunAsUser](/docs/concepts/policy/pod-security-policy/#users-and-groups)के बराबर है।

Linux-विशिष्ट पॉड सुरक्षा प्रसंग विशेषाधिकार जैसे SELinux, AppArmor, Seccomp, या क्षमताएं (POSIX क्षमताएं), और अन्य समर्थित नहीं हैं।

Windows पर विशेषाधिकार प्राप्त कंटेनर [समर्थित नहीं](#compatibility-v1-pod-spec-containers-securitycontext) हैं।

## सहायता प्राप्त करना और समस्या निवारण {#troubleshooting}

कुबेरनेट्स क्लस्टर के समस्या निवारण के लिए आपकी मदद का मुख्य स्रोत शुरू होना चाहिए [समस्या निवारण] (/docs/tasks/debug-application-cluster/troubleshooting/)पृष्ठ के साथ।

कुछ अतिरिक्त, Windows-विशिष्ट समस्या निवारण सहायता शामिल है इस खंड में। लॉग समस्या निवारण का एक महत्वपूर्ण तत्व हैं कुबेरनेट्स में मुद्दे। जब भी आप चाहें, उन्हें शामिल करना सुनिश्चित करें अन्य योगदानकर्ताओं से समस्या निवारण सहायता। SIG Windows [लॉग इकट्ठा करने में योगदान गाइड](https://github.com/kubernetes/community/blob/master/sig-windows/CONTRIBUTING.md#gathering-logs) निर्देशों का पालन करे।

### नोड-स्तरीय समस्या निवारण {#troubleshooting-node}

1. मुझे कैसे पता चलेगा कि `start.ps1` सफलतापूर्वक पूरा हुआ?

    आपको क्यूबलेट, क्यूब-प्रॉक्सी और (यदि आपने फलालैन को अपने नेटवर्किंग के रूप में चुना है) देखना चाहिए समाधान) फ़्लैनल्ड होस्ट-एजेंट प्रक्रियाएं आपके नोड पर चल रही लॉग के साथ चल रही हैं अलग पावरशेल विंडो में प्रदर्शित किया जा रहा है। इसके अलावा, आपका Windows नोड को आपके Kubernetes क्लस्टर में "रेडी" के रूप में सूचीबद्ध किया जाना चाहिए।
    
1. क्या मैं कुबेरनेट्स नोड प्रक्रियाओं को पृष्ठभूमि में सेवाओं के रूप में चलाने के लिए कॉन्फ़िगर कर सकता हूं?

    क्यूबलेट और क्यूब-प्रॉक्सी पहले से ही मूल Windows सेवाओं के रूप में चलाने के लिए कॉन्फ़िगर किए गए हैं,की स्थिति में स्वचालित रूप से सेवाओं को फिर से शुरू करके लचीलापन प्रदान करना विफलता (उदाहरण के लिए एक प्रक्रिया दुर्घटना)। इन्हें कॉन्फ़िगर करने के लिए आपके पास दो विकल्प हैं सेवाओं के रूप में नोड घटक।
    
    1. देशी Windows सेवाओं के रूप में

         आप क्यूबलेट और क्यूब-प्रॉक्सी को `sc.exe` का उपयोग करके देशी Windows सेवाओं के रूप में चला सकते हैं।
         
         ```powershell
             # क्यूबलेट और क्यूब-प्रॉक्सी के लिए दो अलग-अलग कमांड बनाएं
             sc.exe create <component_name> binPath= "<path_to_binary> --service <other_args>"
             
             # कृपया ध्यान दें कि यदि तर्कों में रिक्त स्थान हैं, तो उन्हें बच जाना चाहिए।
             sc.exe create kubelet binPath= "C:\kubelet.exe --service --hostname-override 'minion' <other_args>"
             
             #सेवा शुरू करें
             Start-Service kubelet
             Start-Service kube-proxy
             
             #सेवा बंद करो
             Stop-Service kubelet (-Force)
             Stop-Service kube-proxy (-Force)
             
             # सेवा की स्थिति पूछें
             Get-Service kubelet
             Get-Service kube-proxy
          ```
    1. `nssm.exe` . का उपयोग करना

        आप हमेशा वैकल्पिक सेवा प्रबंधकों का भी उपयोग कर सकते हैं जैसे [nssm.exe](https://nssm.cc/) इन प्रक्रियाओं को चलाने के लिए (फ़्लेनल्ड,क्यूबलेट और क्यूब-प्रॉक्सी) आपके लिए पृष्ठभूमि में। आप इसका इस्तेमाल कर सकते हैं [नमूना स्क्रिप्ट](https://github.com/Microsoft/SDN/tree/master/Kubernetes/flannel/register-svc.ps1),क्यूबलेट, क्यूब-प्रॉक्सी, और flanneld.exe को चलाने के लिए पंजीकृत करने के लिए nssm.exe का लाभ उठाना पृष्ठभूमि में Windows सेवाओं के रूप में।
        
        ```powershell
       register-svc.ps1 -NetworkMode <Network mode> -ManagementIP <Windows Node IP> -ClusterCIDR <Cluster subnet> -KubeDnsServiceIP <Kube-dns Service IP> -LogDir <Directory to place logs>

       # NetworkMode      = The network mode l2bridge (flannel host-gw, also the default value) or overlay (flannel vxlan) chosen as a network solution
       # ManagementIP     = The IP address assigned to the Windows node. You can use ipconfig to find this
       # ClusterCIDR      = The cluster subnet range. (Default value 10.244.0.0/16)
       # KubeDnsServiceIP = The Kubernetes DNS service IP (Default value 10.96.0.10)
       # LogDir           = The directory where kubelet and kube-proxy logs are redirected into their respective output files (Default value C:\k)
       ```
       
       प्रारंभिक समस्या निवारण के लिए, आप [nssm.exe](https://nssm.cc/) में निम्न फ़्लैग का उपयोग आउटपुट फ़ाइल पर stdout और stderr को पुनर्निर्देशित करने के लिए कर सकते हैं:
       
        ```powershell
       nssm set <Service Name> AppStdout C:\k\mysvc.log
       nssm set <Service Name> AppStderr C:\k\mysvc.log
       ```
       
       अतिरिक्त विवरण के लिए, [NSSM - नॉन-सकिंग सर्विस मैनेजर] (https://nssm.cc/usage) देखें।
       
1. माई पॉड्स "कंटेनर क्रिएटिंग" पर अटके हुए हैं या बार-बार रीस्टार्ट हो रहे हैं
    
    जांचें कि आपकी विराम छवि आपके OS संस्करण के साथ संगत है। NS [निर्देश](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/deploying-resources) मान लें कि OS और कंटेनर दोनों ही संस्करण 1803 हैं। यदि आपके पास बाद में है Windows़ का संस्करण, जैसे इनसाइडर बिल्ड, आपको छवियों को समायोजित करने की आवश्यकता है इसलिए। अधिक विवरण के लिए [पॉज़ कंटेनर] (#pause-container) देखें।
    
### नेटवर्क समस्या निवारण {#troubleshooting-network}

1. मेरे Windows पॉड्स में नेटवर्क कनेक्टिविटी नहीं है

    यदि आप वर्चुअल मशीन का उपयोग कर रहे हैं, तो सुनिश्चित करें कि मैक स्पूफिंग सभी VM नेटवर्क एडेप्टर पर **सक्षम** है।

1. मेरे Windows पॉड बाहरी संसाधनों को पिंग नहीं कर सकते हैं

    Windows पॉड्स में ICMP प्रोटोकॉल के लिए प्रोग्राम किए गए आउटबाउंड नियम नहीं हैं। तथापि, TCP/UDP समर्थित है। संसाधनों से कनेक्टिविटी प्रदर्शित करने का प्रयास करते समय लस्टर के बाहर, `ping <IP>` को संबंधित . के साथ बदलें`curl <IP>` कमांड।
    
    यदि आप अभी भी समस्याओं का सामना कर रहे हैं, तो सबसे अधिक संभावना है कि आपका नेटवर्क कॉन्फ़िगरेशन[cni.conf](https://github.com/Microsoft/SDN/blob/master/Kubernetes/flannel/l2bridge/cni/config/cni.conf) कुछ अतिरिक्त ध्यान देने योग्य है। आप इस स्थिर फ़ाइल को कभी भी संपादित कर सकते हैं। NS कॉन्फ़िगरेशन अद्यतन किसी भी नए Kubernetes संसाधनों पर लागू होगा।
             
    Kubernetes नेटवर्किंग आवश्यकताओं में से एक (देखें [कुबेरनेट्स मॉडल] (/docs/concepts/cluster-administration/networking/)) है क्लस्टर संचार के बिना होने के लिए आंतरिक रूप से एनएटी। इस आवश्यकता का सम्मान करने के लिए, एक है [अपवाद सूची](https://github.com/Microsoft/SDN/blob/master/Kubernetes/flannel/l2bridge/cni/config/cni.conf#L20) उन सभी संचारों के लिए जहां आप नहीं चाहते कि आउटबाउंड NAT हो। तथापि,इसका मतलब यह भी है कि आपको उस बाहरी आईपी को बाहर करना होगा जिसे आप क्वेरी करने का प्रयास कर रहे हैं `ExceptionList` से। तभी आपके Windows से आने वाला ट्रैफिक होगा पॉड्स को बाहरी दुनिया से प्रतिक्रिया प्राप्त करने के लिए सही ढंग से SNAT'ed किया जाना चाहिए। इसमें संबंध में, आपकी `ExceptionList` `cni.conf` में इस प्रकार दिखनी चाहिए:
    
    ```conf
   "ExceptionList": [
                   "10.244.0.0/16",  # Cluster subnet
                   "10.96.0.0/12",   # Service subnet
                   "10.127.130.0/24" # Management (host) subnet
               ]
   ```

1. मेरा Windows नोड `नोडपोर्ट` प्रकार की सेवाओं तक नहीं पहुंच सकता है

    नोड से स्थानीय नोडपोर्ट पहुंच स्वयं विफल हो जाती है। यह एक ज्ञात है सीमा। NodePort एक्सेस अन्य नोड्स या बाहरी क्लाइंट से काम करता है।
    
1. कंटेनर के vNICs और HNS एंडपॉइंट डिलीट जा रहे हैं

    यह समस्या तब हो सकती है जब `होस्टनाम-ओवरराइड` पैरामीटर को पास नहीं किया जाता है [क्यूब-प्रॉक्सी] (/ डॉक्स/संदर्भ/कमांड-लाइन-टूल्स-रेफरेंस/क्यूब-प्रॉक्सी/)। हल उपयोगकर्ताओं को होस्टनाम को क्यूब-प्रॉक्सी में निम्नानुसार पास करना होगा:
    
    ```powershell
   C:\k\kube-proxy.exe --hostname-override=$(hostname)
   ```
   
1. फलालैन के साथ, क्लस्टर में फिर से शामिल होने के बाद मेरे नोड्स में समस्याएं आ रही हैं

    जब भी पहले से हटाए गए नोड को क्लस्टर में फिर से जोड़ा जाता है, तो flannelD नोड को एक नया पॉड सबनेट असाइन करने का प्रयास करता है। उपयोगकर्ता पुराने पॉड को हटा दें निम्न पथों में सबनेट कॉन्फ़िगरेशन फ़ाइलें:
    
    ```powershell
   Remove-Item C:\k\SourceVip.json
   Remove-Item C:\k\SourceVipRequest.json
   ```
    
1. `Start.ps1` को लॉन्च करने के बाद, फ़्लैनेल्ड "वेटिंग फॉर द नेटवर्क टू क्रिएटेड" में फंस गया है

    इस [मुद्दे](https://github.com/coreos/flannel/issues/1066) की कई रिपोर्टें हैं; सबसे अधिक संभावना है कि यह एक समय का मुद्दा है जब फलालैन नेटवर्क का प्रबंधन आईपी सेट किया जाता है। एक समाधान यह है कि `start.ps1` को फिर से लॉन्च किया जाए या इसे मैन्युअल रूप से इस प्रकार फिर से लॉन्च किया जाए:
    
    ```powershell
   [Environment]::SetEnvironmentVariable("NODE_NAME", "<Windows_Worker_Hostname>")
   C:\flannel\flanneld.exe --kubeconfig-file=c:\k\config --iface=<Windows_Worker_Node_IP> --ip-masq=1 --kube-subnet-mgr=1
   ```
   
1. मेरे Windows पॉड्स से `/run/flannel/subnet.env` गायब होने के कारण लॉन्च नहीं हो सकते 

    यह इंगित करता है कि फ्लैनेल सही ढंग से लॉन्च नहीं हुआ। आप या तो कोशिश कर सकते हैं `flanneld.exe` को पुनः आरंभ करने के लिए या आप फ़ाइलों को मैन्युअल रूप से कॉपी कर सकते हैं कुबेरनेट्स मास्टर पर `/run/flannel/subnet.env` से `C:\run\flannel\subnet.env` Windows वर्कर नोड पर और `FLANNEL_SUBNET` पंक्ति को भिन्न में संशोधित करें संख्या। उदाहरण के लिए, यदि नोड सबनेट 10.244.4.1/24 वांछित है:
    
    ```env
   FLANNEL_NETWORK=10.244.0.0/16
   FLANNEL_SUBNET=10.244.4.1/24
   FLANNEL_MTU=1500
   FLANNEL_IPMASQ=true
   ```
   
1. मेरा Windows नोड सेवा IP का उपयोग करके मेरी सेवाओं तक नहीं पहुंच सकता है

    यह Windows पर नेटवर्किंग स्टैक की एक ज्ञात सीमा है। हालाँकि, Windows पॉड्स सर्विस आईपी तक पहुंच सकते हैं।
    
1. क्यूबलेट शुरू करते समय कोई नेटवर्क एडेप्टर नहीं मिला

    कुबेरनेट्स नेटवर्किंग के काम करने के लिए Windows नेटवर्किंग स्टैक को एक वर्चुअल एडेप्टर की आवश्यकता होती है। यदि निम्न कमांड कोई परिणाम नहीं देता है (व्यवस्थापक शेल में), वर्चुअल नेटवर्क निर्माण - क्यूबलेट के काम करने के लिए एक आवश्यक शर्त - विफल हो गया है:
    
   ```powershell
   Get-HnsNetwork | ? Name -ieq "cbr0"
   Get-NetAdapter | ? Name -Like "vEthernet (Ethernet*"
   ```
   
    अक्सर यह start.ps1 स्क्रिप्ट के [इंटरफ़ेसनाम](https://github.com/microsoft/SDN/blob/master/Kubernetes/flannel/start.ps1#L7) पैरामीटर को संशोधित करने के लिए उपयुक्त होता है, ऐसे मामलों में जहां होस्ट के नेटवर्क एडेप्टर "ईथरनेट" नहीं है। अन्यथा, वर्चुअल नेटवर्क निर्माण के दौरान त्रुटियां हैं या नहीं यह देखने के लिए `start-kubelet.ps1` स्क्रिप्ट के आउटपुट से परामर्श करें।
    
1. DNS रिज़ॉल्यूशन ठीक से काम नहीं कर रहा है

    इस [अनुभाग](#dns-limitations) में Windows के लिए DNS सीमाओं की जाँच करें।

1. `kubectl port-forward` विफल हो जाता है "पोर्ट अग्रेषण करने में असमर्थ: wincat नहीं मिला"

    यह कुबेरनेट्स 1.15 में पॉज़ इंफ्रास्ट्रक्चर कंटेनर `mcr.microsoft.com/oss/kubernetes/pause:1.4.1` में `wincat.exe` को शामिल करके लागू किया गया था। कुबेरनेट्स के समर्थित संस्करण का उपयोग करना सुनिश्चित करें।
    अगर आप अपना खुद का पॉज़ इंफ्रास्ट्रक्चर कंटेनर बनाना चाहते हैं तो [wincat](https://github.com/kubernetes/kubernetes/tree/master/build/pause/windows/wincat) को शामिल करना सुनिश्चित करें।
    
1. मेरा कुबेरनेट्स इंस्टॉलेशन विफल हो रहा है क्योंकि मेरा Windows सर्वर नोड प्रॉक्सी के पीछे है

    यदि आप किसी प्रॉक्सी के पीछे हैं, तो निम्न PowerShell परिवेश चर परिभाषित किए जाने चाहिए:
    
      ```PowerShell
   [Environment]::SetEnvironmentVariable("HTTP_PROXY", "http://proxy.example.com:80/", [EnvironmentVariableTarget]::Machine)
   [Environment]::SetEnvironmentVariable("HTTPS_PROXY", "http://proxy.example.com:443/", [EnvironmentVariableTarget]::Machine)
   ```
   
### आगे की जांच पड़ताल

यदि इन चरणों से आपकी समस्या का समाधान नहीं होता है, तो आप निम्न के माध्यम से Kubernetes में Windows नोड्स पर Windows कंटेनर चलाने में सहायता प्राप्त कर सकते हैं:

* स्टैक ओवरफ्लो [Windows सर्वर कंटेनर] (https://stackoverflow.com/questions/tagged/windows-server-container) विषय
* Kubernetes आधिकारिक फोरम [discuss.kubernetes.io](https://discuss.kubernetes.io/)
* कुबेरनेट्स स्लैक [#SIG-Windows चैनल](https://kubernetes.slack.com/messages/sig-windows)

### रिपोर्टिंग समस्याएं और सुविधा अनुरोध

यदि आपके पास बग जैसा दिखता है, या आप करना चाहते हैं एक सुविधा अनुरोध करें, कृपया इसका उपयोग करें[GitHub इश्यू ट्रैकिंग सिस्टम](https://github.com/kubernetes/kubernetes/issues)। आप मुद्दों को खोल सकते हैं[GitHub](https://github.com/kubernetes/kubernetes/issues/new/choose) और असाइन करें उन्हें SIG-Windows. आपको सबसे पहले मुद्दों की सूची खोजनी चाहिए यदि यह थी पहले रिपोर्ट की गई और इस मुद्दे पर अपने अनुभव के साथ टिप्पणी करें और अतिरिक्त जोड़ें लॉग SIG-Windows Slack भी कुछ प्रारंभिक समर्थन प्राप्त करने का एक अच्छा अवसर है और टिकट बनाने से पहले समस्या निवारण के उपाय।

यदि कोई बग फाइल कर रहा है, तो कृपया समस्या को पुन: उत्पन्न करने के तरीके के बारे में विस्तृत जानकारी शामिल करें, जैसे:

* Kubernetes संस्करण: `kubectl संस्करण` . से आउटपुट
* पर्यावरण विवरण: क्लाउड प्रदाता, ओएस डिस्ट्रो, नेटवर्किंग पसंद और कॉन्फ़िगरेशन, और डॉकर संस्करण 
* समस्या को पुन: उत्पन्न करने के लिए विस्तृत कदम
* [प्रासंगिक लॉग](https://github.com/kubernetes/community/blob/master/sig-windows/CONTRIBUTING.md#gathering-logs)

यदि आप इस मुद्दे पर `/sig windows` के साथ टिप्पणी करके समस्या को **sig/windows** के रूप में टैग करते हैं तो यह मदद करता है। यह लाने में मदद करता है
एक SIG Windows सदस्य के ध्यान में मुद्दा

## {{% heading "whatsnext" %}}

### परिनियोजन उपकरण

Kubeadm टूल आपको नियंत्रण प्रदान करते हुए Kubernetes क्लस्टर को परिनियोजित करने में मदद करता है क्लस्टर को प्रबंधित करने के लिए विमान, और आपके कार्यभार को चलाने के लिए नोड्स। [Windows नोड्स जोड़ना](/docs/tasks/administer-cluster/kubeadm/adding-windows-nodes/))
कुबेदम का उपयोग करके अपने क्लस्टर में Windows नोड्स को तैनात करने का तरीका बताता है।

कुबेरनेट्स [क्लस्टर एपीआई](https://cluster-api.sigs.k8s.io/) प्रोजेक्ट Windows नोड्स की तैनाती को स्वचालित करने के साधन भी प्रदान करता है।

### Windows वितरण चैनल

Windows वितरण चैनलों की विस्तृत व्याख्या के लिए [Microsoft दस्तावेज़ीकरण](https://docs.microsoft.com/en-us/windows-server/get-started-19/serviceing-channels-19) देखें।

विभिन्न Windows सर्वर सर्विसिंग चैनलों पर जानकारी उनके समर्थन मॉडल सहित यहां पाया जा सकता है [Windows सर्वर सर्विसिंग चैनल](https://docs.microsoft.com/en-us/windows-server/get-started/servicing-channels-comparison)।

