package main

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "net/http"
    "log"
    "time"
    "os/exec"
    "strings"
    "fmt"
    "os"
    //"runtime"
    //"github.com/prometheus/security_exporter/collector"
    "github.com/fsnotify/fsnotify"
)

type SecurityManager struct {
    Zone         string
    ReverseShellDesc *prometheus.Desc
    FailPasswordDesc *prometheus.Desc
    FsChangeDesc *prometheus.Desc
    // ... many more fields
}

//the total number of reverseShell 
//检查系统后门反弹数量
func reverseShell(t string) int {
    cmd := exec.Command("/bin/sh","-c",`lsof | grep TCP | awk '{print $1}'`)
    out, err := cmd.Output()
    if err != nil {
        fmt.Println(err)
    }
    return strings.Count(string(out),t)
}

//the total number of failPassword
//检查系统ssh密码登录错误数量
func failPassword(t string) int {
    cmd := exec.Command("/bin/sh","-c",`cat /var/log/secure`)
    out, err := cmd.Output()
    if err != nil {
        fmt.Println(err)
    }
    return strings.Count(string(out),t)
}

//Get the hostname
//获取主机名
func getHostname() string {
    host, err := os.Hostname()
    if err != nil {
        fmt.Printf("%s", err)
    } 
    return host
}


//Monitor file change
//检查系统配置信息被篡改数量
func fsChange(t string) int {
    cmd := exec.Command("/bin/sh","-c",`cat /tmp/fsnotify.log`)
    out, err := cmd.Output()
    if err != nil {
        fmt.Println(err)
    }
    return strings.Count(string(out),t)

}

//write fsnotify file
func tracefile(str_content string)  {
    fd,_:=os.OpenFile("/tmp/fsnotify.log",os.O_RDWR|os.O_CREATE|os.O_APPEND,0644)
    fd_time:=time.Now().Format("2006-01-02 15:04:05");
    fd_content:=strings.Join([]string{fd_time,"    ",str_content,"\n"},"")
    buf:=[]byte(fd_content)
    fd.Write(buf)
    fd.Close()
}

//Monitor file change fsnotify

func fsnotifyInit(){
    // 监控路径列表
    paths := []string{
        "/etc",
        "/sbin",
        "/bin",
        "/usr/sbin",
        "/usr/bin",
    }
    //判断文件是否存在并创建
    _, err := os.Stat("/tmp/fsnotify.log")
    if os.IsNotExist(err) {
        file,_:= os.Create("/tmp/fsnotify.log")
        defer file.Close()
    }

    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        log.Fatalf("Failed to create watcher: %s", err)
    }
    defer watcher.Close()

    exit := make(chan bool)

    go func() {
        for {
            select {
            case e := <-watcher.Events:
                //log.Println("修改文件：" + e.Name)
                //log.Println("修改类型：" + e.Op.String())
                tracefile(e.Name + "   " + e.Op.String())
            case err := <-watcher.Errors:
                log.Printf("Watcher error: %s\n", err.Error()) // No need to exit here
            }
        }
    }()

    log.Println("安装检测模块...")
    for _, path := range paths {
        log.Printf("正在检测: %s\n", path)
        err = watcher.Add(path)
        if err != nil {
            log.Fatalf("Failed to watch directory: %s", err)
        }
    }

    //select{}
    <-exit 
    //runtime.Goexit()
}


// Simulate prepare the data
//模拟准备数据
func (c *SecurityManager) SecurityState() (
    reverseCountByHost map[string]int, failpasswdCountByHost map[string]int,  fschangeCountByHost map[string]int,
) {
    // Just example fake data.
    var shellsum int
    shellsum = reverseShell("sh\n") + reverseShell("py\n")
    reverseCountByHost = map[string]int{
        getHostname(): shellsum,
    }
    failpasswdCountByHost = map[string]int{
        //"bar.example.org": 2001,
        getHostname(): failPassword("Failed password"),
    }
    //获取当前日期
    day := time.Now().Format("2006-01-02")
    fschangeCountByHost = map[string]int{
        //getHostname(): fsChange("/etc"),
        getHostname(): fsChange(day),
    }

    return
}

// Describe simply sends the  Descs in the struct to the channel.
//将描述信息放入管道
func (c *SecurityManager) Describe(ch chan<- *prometheus.Desc) {
    ch <- c.ReverseShellDesc
    ch <- c.FailPasswordDesc
    ch <- c.FsChangeDesc
}

//将收集信息放入prometheus模型
func (c *SecurityManager) Collect(ch chan<- prometheus.Metric) {
    reverseCountByHost, failpasswdCountByHost, fsChangeCountByHost := c.SecurityState()
    for host, reverseCount := range reverseCountByHost {
        ch <- prometheus.MustNewConstMetric(
            c.ReverseShellDesc,
            prometheus.CounterValue,
            float64(reverseCount),
            host,
        )
    }

    for host, failpasswdCount := range failpasswdCountByHost {
        ch <- prometheus.MustNewConstMetric(
            c.FailPasswordDesc,
            prometheus.CounterValue,
            float64(failpasswdCount),
            host,
        )
    }

    for host, fsChangeCount := range fsChangeCountByHost {
        ch <- prometheus.MustNewConstMetric(
            c.FsChangeDesc,
            prometheus.CounterValue,
            float64(fsChangeCount),
            host,
        )
    }

}

// SecurityManager instances with the same registry.
//注册实例
func NewSecurityManager(zone string) *SecurityManager {
    return &SecurityManager{
        Zone: zone,
        ReverseShellDesc: prometheus.NewDesc(
            "reverse_shell_total",
            "Number of Reverse Shell.",
            []string{"host"},
            prometheus.Labels{"zone": zone},
        ),
        FailPasswordDesc: prometheus.NewDesc(
            "fail_password_total",
            "Number of Fail Password in /var/log/secure.",
            []string{"host"},
            prometheus.Labels{"zone": zone},
        ),

        FsChangeDesc: prometheus.NewDesc(
            "file_change_total",
            "Number of Change in /etc.",
            []string{"host"},
            prometheus.Labels{"zone": zone},
        ),

    }
}


//主运行函数
func main() {
    //collector.Test()
    //将fsnotifyInit函数放入线程，防止主进程阻塞 
    go func() {    
        fsnotifyInit()
    }()

    workerDB := NewSecurityManager("datacenter")

    // Since we are dealing with custom Collector implementations, it might
    // be a good idea to try it out with a pedantic registry.
    reg := prometheus.NewPedanticRegistry()
    reg.MustRegister(workerDB)


    http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte(`<html>
                    <head><title>Security Exporter</title></head>
                    <body>

                    <p><a href=" /metrics ">Metrics</a></p>
                    </body>
                    </html>`))
    })
    log.Fatal(http.ListenAndServe(":9933", nil))


}
