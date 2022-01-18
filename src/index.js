document.addEventListener('DOMContentLoaded', function(){
    
    let virustotalKey = "vtkey" in localStorage?localStorage.getItem("vtkey"):"";
    let abuseipKey = "aikey" in localStorage?localStorage.getItem("aikey"):"";
    let ibmxforceKey = "ibmkey" in localStorage?localStorage.getItem("ibmkey"):"";
    let ibmxforcePass = "ibmpass" in localStorage?localStorage.getItem("ibmpass"):"";
    
    const vtinput = document.querySelector('#inp-virus');
    const aiinput = document.querySelector('#inp-abuse');
    const ibminput = document.querySelector('#inp-ibm1');
    const ibmpsw = document.querySelector('#inp-ibm2');
    const changeconfig = document.querySelector('#change');

    vtinput.value = virustotalKey;
    aiinput.value = abuseipKey;
    ibminput.value = ibmxforceKey;
    ibmpsw.value = ibmxforcePass;

    changeconfig.addEventListener('click', function(){
        localStorage.setItem('vtkey', vtinput.value);
        localStorage.setItem('aikey', aiinput.value);
        localStorage.setItem('ibmkey', ibminput.value);
        localStorage.setItem('ibmpass', ibmpsw.value);

        virustotalKey = vtinput.value;
        abuseipKey = aiinput.value;
        ibmxforceKey = ibminput.value;
        ibmxforcePass = ibmpsw.value;
    });
     
    let reportcole = {};

    async function render(ip,rpcole){

        let vtobj = rpcole.find(o => o.provider === "virustotal");
        let aiobj = rpcole.find(o => o.provider === "abuseip");
        let ibmobj = rpcole.find(o => o.provider === "ibmxforce");
        let avobj = rpcole.find(o => o.provider === "alienvault");

        function dangerColor(prov,isIBM){
            if(isIBM && prov.score === "1"){
                prov.score = "0";
            }
            if(prov.score){
                if(prov.score != "0"){
                    return "#622c31";
                }else{
                    return "#2d422f";
                }
            }
        }

        document.querySelector('#render').innerHTML += 
        `
        <tr>
            <td>${ip}</td>
            <td style='background-color:${dangerColor(vtobj)}'>${vtobj?vtobj.score:""}</td>
            <td style='background-color:${dangerColor(aiobj)}'>${aiobj?aiobj.score+'%':""}</td>
            <td style='background-color:${dangerColor(ibmobj,1)}'>${ibmobj?ibmobj.score:""}</td>
            <td style='background-color:${dangerColor(avobj)}'>${avobj?avobj.score:""}</td>
        </tr>
        `;
    }

    async function addReport(ip, provider, value){
      if(reportcole[ip] === undefined){  
        reportcole[ip] = [];
      }
      reportcole[ip].push({
        provider:provider,
        score:value.toString(),
      })
    }

    async function getAnalysis(ip){
        let checkVT = document.getElementById("cvt").checked;
        let checkAI = document.getElementById("cai").checked;
        let checkIBM = document.getElementById("cibm").checked;
        let checkAV = document.getElementById("cav").checked;

        if(reportcole[ip] === undefined){
            document.querySelector('#search').disabled = "true";
            document.body.style.cursor='wait';
            if(checkVT){
                await getVirusTotalAnalysis(ip);
            }
            if(checkAI){
                await getAbuseIpAnalysis(ip);
            }
            if(checkIBM){
                await getIBMXForceAnalysis(ip);
            }
            if(checkAV){
                await getAlienAnalysis(ip);
            }
            await render(ip,reportcole[ip]);
            document.body.style.cursor='default';
            document.querySelector('#search').removeAttribute("disabled");
        }else{
            console.log("Repetido:"+ip);
        }
    }

    async function getVirusTotalAnalysis(ipadress){
        const apikey = virustotalKey;
        const options = {
            method: 'GET',
            headers: {
            Accept: 'application/json',
            'x-apikey': apikey
            }
        };
        try{
            let response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ipadress}`, options)
            .then(response => response.json())
            .then(async function(response){
                await addReport(ipadress,'virustotal',response.data.attributes.last_analysis_stats.malicious);
            })
        } catch(err){
            console.log(err);
        }
    }
    
    async function getAbuseIpAnalysis(ipadress){
        const apikey = abuseipKey;
        const options = {
            method: 'GET',
            headers: {
            Accept: 'application/json',
            'key': apikey
            }
        };
        await fetch(`https://api.abuseipdb.com/api/v2/check/?ipAddress=${ipadress}`, options)
        .then(response => response.json())
        .then(response => addReport(ipadress,'abuseip',response.data.abuseConfidenceScore))
        .catch(err => console.error(err));
    }
    
    async function getIBMXForceAnalysis(ipadress,attempt){
        const apikey = ibmxforceKey;
        const pass = ibmxforcePass;
        const options = {
            method: 'GET',
            headers: {
            Accept: 'application/json',
            Authorization: 'Basic ' + btoa(apikey+':'+pass)
            },
        };
        await fetch(`https://api.xforce.ibmcloud.com/api/ipr/${ipadress}`, options)
        .then(response => response.json())
        .then(response => addReport(ipadress,'ibmxforce',response.score))
        .catch(err => console.error(err));
    }
    
    async function getAlienAnalysis(ipadress){
        const options = {
            method: 'GET',
            headers: {
            Accept: 'application/json',
            },
        };
        await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ipadress}/general`, options)
        .then(response => response.json())
        .then(response => addReport(ipadress,'alienvault',response.pulse_info.count))
        .catch(err => console.error(err))
    }

    String.prototype.trim = function() {
        try {
            return this.replace(/^\s+|\s+$/g, "");
        } catch(e) {
            return this;
        }
    }

    function checkIfValidIP(str) {
        // Regular expression to check if string is a IP address
        const regexExp = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/gi;
        return regexExp.test(str);
    }

    function readCSV(csv){
        let options = {separator:";"}
        let data = $.csv.toArrays(csv,options);
        data.shift();
        let iplist = [];
        for(let c=0;c<data.length;c++){
            iplist[c] = data[c][0];
        }
        let interval = 5000; 
        iplist.forEach((ip,index)=>{
            setTimeout(()=>{
                console.log(index+'- Analise:'+ip);
                getAnalysis(ip);
            }, index * interval)
        })
    }

    function exportToExcel(){
        var htmls = "";
        var uri = 'data:application/vnd.ms-excel;base64,';
        var template = '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40"><head><!--[if gte mso 9]><xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet><x:Name>{worksheet}</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml><![endif]--></head><body><table>{table}</table></body></html>'; 
        var base64 = function(s) {
            return window.btoa(unescape(encodeURIComponent(s)))
        };

        var format = function(s, c) {
            return s.replace(/{(\w+)}/g, function(m, p) {
                return c[p];
            })
        };

        htmls = document.getElementsByTagName('table')[0].innerHTML;

        var ctx = {
            worksheet : 'Worksheet',
            table : htmls
        }

        var link = document.createElement("a");
        var date = new Date;
        let hour = date.getHours();
        let minutes = date.getMinutes();
        var day = date.getDate();
        var month = date.getMonth()+1;
        var year = date.getFullYear();

        link.download = "DIP-Report["+hour+"h"+minutes+"min"+"]["+day+"-"+month+"-"+year+"].xls";
        link.href = uri + base64(format(template, ctx));
        link.click();
    }

    // Buttons
    document.querySelector('#search').addEventListener('click',function(){
        let ip = document.querySelector('#ipbox').value.trim();
        if(ip){
            if(checkIfValidIP(ip)){
                getAnalysis(ip);
            }else{
                console.log('erro');
            }
        }else{
            confirm("endereço de ip inválido");         
        }
    })

    document.querySelector('#upload').addEventListener('change',function(e){
        let getFile = new FileReader();
        let file = document.querySelector('#upload').files[0];

        getFile.onload= function(){
            readCSV(getFile.result)
        }
        getFile.readAsText(file);
    })

    document.querySelector('#export').addEventListener('click',function(){
        console.log(JSON.stringify(reportcole, null, 2));
        exportToExcel();
    })
   
    document.querySelector('#trash').addEventListener('click',function(){
        reportcole = [];
        document.querySelector('#render').innerHTML = "";
    })

    let gear = document.querySelector('#gear');       
    gear.addEventListener('click',function(){
        document.querySelector('.modal').style.display = "flex";
    })

    let cancel = document.querySelector('#cls-modal');
    cancel.addEventListener('click', function(){
        document.querySelector('.modal').style.display = "none";
    })
})