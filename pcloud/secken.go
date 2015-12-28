/*
* Copyright 2014-2015 Secken, Inc. All Rights Reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*
* NOTICE: All information contained herein is, and remains
* the property of Secken, Inc. and its suppliers, if any.
* The intellectual and technical concepts contained
* herein are proprietary to Secken, Inc. and its suppliers
* and may be covered by China and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Secken, Inc..
*
* 注意：此处包含的所有信息，均属于Secken, Inc.及其供应商的私有财产。
* 此处包含的所有知识、专利均属于Secken, Inc.及其供应商，属于商业秘密，
* 并受到中国和其他国家的法律保护。这些信息及本声明，除非事先得到
* Secken, Inc.的书面授权，否则严禁复制或传播。
*
*
* @author      Zxg (xiangangzhang@secken.com)
* @version     0.1
* @project     pcloud sdk part
* @start       20151218
*/

package pcloud

import (
    "io"
    "fmt"
    "net"
    "time"
    "sort"
    "bytes"
    "errors"
    "strconv"
    "net/url"
    "net/http"
    "io/ioutil"
    "crypto/sha1"
    "encoding/json"
    "mime/multipart"
)

const (
    baseurl = "https://api.sdk.yangcong.com/"
)

type ReturnBase struct {
    Status int `json:"status"`
    Description string `json:"description"`
    Signature string `json:"signature"`
    appkey string
}

func (r *ReturnBase) sha1() string {
    src := make(map[string]string)
    src["status"] = string(strconv.Itoa(r.Status))
    src["description"] = r.Description
    var keys []string
    for k, _ := range src {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    var data string
    for _, k := range keys {
        l := k + "=" + src[k]
        data += l
    }
    s := sha1.New()
    io.WriteString(s,data+r.appkey)
    sig := fmt.Sprintf("%x",s.Sum(nil))
    if sig != r.Signature {
        return r.Description
    }
    return ""
}

type QrcodeForAuth struct {
    appid string
    appkey string
    signature string
    authtype string
    actiontype string
    actiondetails string
    callback string
}

func NewQrcodeForAuth(id, key, atype, ntype, details, call string) *QrcodeForAuth {
    return &QrcodeForAuth{appid:id, appkey:key, authtype:atype, actiontype:ntype, actiondetails:details, callback:call}
}

func (q *QrcodeForAuth) sha1() (string, error){
    u, err := url.Parse(baseurl+"qrcode_for_auth")
    if err != nil {
        return "", err
    }
    g := u.Query()
    src := make(map[string]string)
    src["app_id"] = q.appid
    if q.authtype != "" {
        src["auth_type"] = q.authtype
    }
    if q.actiontype != "" {
        src["action_type"] = q.actiontype
    }
    if q.actiondetails != "" {
        src["action_details"] = q.actiondetails
    }
    if q.callback != "" {
        src["callback"] = q.callback
    }
    var keys []string
    for k, v := range src {
        keys = append(keys, k)
        g.Set(k,v)
    }
    sort.Strings(keys)
    var data string
    for _, k := range keys {
        l := k + "=" + src[k]
        data += l
    }
    s := sha1.New()
    io.WriteString(s,data+q.appkey)
    q.signature = fmt.Sprintf("%x",s.Sum(nil))
    g.Set("signature", q.signature)
    u.RawQuery = g.Encode()
    return u.String(), nil
}

func (q *QrcodeForAuth) Get() (*QrcodeStatus, error){
    var Qrstatus QrcodeStatus
    geturl, err := q.sha1()
    if err != nil {
        return &Qrstatus, err
    }
    res, err := http.Get(geturl)
    if err != nil {
        return &Qrstatus, err
    }
    result, err := ioutil.ReadAll(res.Body)
    if err != nil {
        return &Qrstatus, err
    }
    err = json.Unmarshal(result, &Qrstatus)
    if err != nil {
        fmt.Println(err)
        return &Qrstatus, err
    }
    Qrstatus.appkey = q.appkey
    if str := Qrstatus.sha1(); str != "" {
        return &Qrstatus, errors.New(str)
    }
    res.Body.Close()
    return &Qrstatus, nil
}

type QrcodeStatus struct {
    ReturnBase
    Eventid string `json:"event_id"`
    Qrcodeurl string `json:"qrcode_url"`
    Qrcodedata string `json:"qrcode_data"`
    appkey string
}

func (r *QrcodeStatus) sha1() string {
    src := make(map[string]string)
    src["status"] = string(strconv.Itoa(r.Status))
    src["description"] = r.Description
    src["event_id"] = r.Eventid
    src["qrcode_url"] = r.Qrcodeurl
    src["qrcode_data"] = r.Qrcodedata
    var keys []string
    for k, _ := range src {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    var data string
    for _, k := range keys {
        l := k + "=" + src[k]
        data += l
    }
    s := sha1.New()
    io.WriteString(s,data+r.appkey)
    sig := fmt.Sprintf("%x",s.Sum(nil))
    if sig != r.Signature {
        return r.Description
    }
    return ""
}

func (r *QrcodeStatus) GetStatus() int {
    return r.Status
}

func (r *QrcodeStatus) GetQrcodeUrl() string {
    return r.Qrcodeurl
}

type QueryAuthToken struct {
    appid string
    appkey string
    authtoken string
    signature string
}

func NewQueryAuthToken(id,key,token string) *QueryAuthToken {
    return &QueryAuthToken{appid:id, appkey:key, authtoken:token}
}

func (q *QueryAuthToken) sha1() (string, error){
    u, err := url.Parse(baseurl+"query_auth_token")
    if err != nil {
        return "", err
    }
    g := u.Query()
    src := make(map[string]string)
    src["app_id"] = q.appid
    src["auth_token"] = q.authtoken
    var keys []string
    for k, v := range src {
        keys = append(keys, k)
        g.Set(k,v)
    }
    sort.Strings(keys)
    var data string
    for _, k := range keys {
        l := k + "=" + src[k]
        data += l
    }
    s := sha1.New()
    io.WriteString(s,data+q.appkey)
    q.signature = fmt.Sprintf("%x",s.Sum(nil))
    g.Set("signature", q.signature)
    u.RawQuery = g.Encode()
    return u.String(), nil
}

func (q *QueryAuthToken) Get() (*ReturnBase, error){
    var Qrstatus ReturnBase
    geturl, err := q.sha1()
    if err != nil {
        return &Qrstatus, err
    }
    res, err := http.Get(geturl)
    if err != nil {
        return &Qrstatus, err
    }
    result, err := ioutil.ReadAll(res.Body)
    if err != nil {
        return &Qrstatus, err
    }
    err = json.Unmarshal(result, &Qrstatus)
    if err != nil {
        fmt.Println(err)
        return &Qrstatus, err
    }
    Qrstatus.appkey = q.appkey
    if str := Qrstatus.sha1(); str != "" {
        return &Qrstatus, errors.New(str)
    }
    res.Body.Close()
    return &Qrstatus, nil
}

type ResultReturn struct {
    ReturnBase
    Eventid string `json:"event_id"`
    Uid string `json:"uid"`
}

func (r *ResultReturn) sha1() string{
    src := make(map[string]string)
    src["status"] = string(strconv.Itoa(r.Status))
    src["description"] = r.Description
    src["event_id"] = r.Eventid
    src["uid"] = r.Uid
    var keys []string
    for k, _ := range src {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    var data string
    for _, k := range keys {
        l := k + "=" + src[k]
        data += l
    }
    s := sha1.New()
    io.WriteString(s,data+r.appkey)
    sig := fmt.Sprintf("%x",s.Sum(nil))
    if sig != r.Signature {
        return r.Description
    }
    return ""
}

type EventResult struct {
    appid string
    appkey string
    eventid string
    signature string
}

func NewEventResult(id, key, eventid string) *EventResult{
    return &EventResult{appid:id, appkey:key, eventid:eventid}
}

func (e *EventResult) sha1() (string, error){
    u, err := url.Parse(baseurl+"event_result")
    if err != nil {
        return "", err
    }
    g := u.Query()
    src := make(map[string]string)
    src["app_id"] = e.appid
    src["event_id"] = e.eventid
    var keys []string
    for k, v := range src {
        keys = append(keys, k)
        g.Set(k,v)
    }
    sort.Strings(keys)
    var data string
    for _, k := range keys {
        l := k + "=" + src[k]
        data += l
    }
    s := sha1.New()
    io.WriteString(s,data+e.appkey)
    e.signature = fmt.Sprintf("%x",s.Sum(nil))
    g.Set("signature", e.signature)
    u.RawQuery = g.Encode()
    return u.String(), nil
}

func (e *EventResult) Get() (*ResultReturn, error){
    var Qrstatus ResultReturn
    geturl, err := e.sha1()
    if err != nil {
        return &Qrstatus, err
    }
    res, err := http.Get(geturl)
    if err != nil {
        return &Qrstatus, err
    }
    result, err := ioutil.ReadAll(res.Body)
    if err != nil {
        return &Qrstatus, err
    }
    err = json.Unmarshal(result, &Qrstatus)
    if err != nil {
        fmt.Println(err)
        return &Qrstatus, err
    }
    fmt.Println(Qrstatus)
    Qrstatus.appkey = e.appkey
    if str := Qrstatus.sha1(); str != "" {
        return &Qrstatus, errors.New(str)
    }
    res.Body.Close()
    return &Qrstatus, nil
}

type RealtimeAuthorization struct {
    appid string
    appkey string
    uid string
    signature string
    authtype string
    actiontype string
    actiondetails string
    callback string
}

func NewRealtimeAuthorization(id, key, uid, atype, actype, adetails, callback string) *RealtimeAuthorization {
    return &RealtimeAuthorization{appid:id, appkey:key, uid:uid, authtype:atype, actiontype:actype,actiondetails:adetails,callback:callback}
}

func (r *RealtimeAuthorization) sha1() (string, *http.Request,  error){
    body := new(bytes.Buffer)
    u, err := url.Parse(baseurl+"realtime_authorization")
    if err != nil {
        return "", nil, err
    }
    g := u.Query()
    src := make(map[string]string)
    src["app_id"] = r.appid
    if r.uid != "" {
        src["uid"] = r.uid
    }
    if r.authtype != "" {
        src["auth_type"] = r.authtype
    }
    if r.actiontype != "" {
        src["action_type"] = r.actiontype
    }
    if r.actiondetails != "" {
        src["action_details"] = r.actiondetails
    }
    if r.callback != "" {
        src["callback"] = r.callback
    }
    var keys []string
    for k, v := range src {
        keys = append(keys, k)
        g.Set(k,v)
    }
    sort.Strings(keys)
    var data string
    for _, k := range keys {
        l := k + "=" + src[k]
        data += l
    }
    s := sha1.New()
    io.WriteString(s,data+r.appkey)
    r.signature = fmt.Sprintf("%x",s.Sum(nil))
    g.Set("signature", r.signature)
    u.RawQuery = g.Encode()
    writer := multipart.NewWriter(body)
    src["signature"] = r.signature
    for k, v := range src {
        writer.WriteField(k, v)
    }
    writer.Close()
    rq, err := http.NewRequest("POST", baseurl+"realtime_authorization", body)
    if err != nil {
        fmt.Println("newrequest", err)
        return u.String(), nil, err
    }
    rq.Header.Set("Accept", "*/*")
    rq.Header.Set("Expect", "100-continue")
    rq.Header.Set("Content-Type", writer.FormDataContentType())
    return u.String(), rq, nil
}

var httpTimeOut = time.Duration(2*time.Second)
func dto(nw, addr string) (net.Conn, error) {
    return net.DialTimeout(nw, addr, httpTimeOut)
}

func (r *RealtimeAuthorization) Post() (*RealtimeReturn, error){
    var Qrstatus RealtimeReturn
    _, rq, err := r.sha1()
    if err != nil {
        return &Qrstatus, err
    }
    tr := http.Transport {
        Dial: dto,
    }
    cli := &http.Client{
        Transport: &tr,
    }
    do, err := cli.Do(rq)
    if err != nil {
        fmt.Println("cli do", err)
        return &Qrstatus, err
    }
    if do.StatusCode != 200 {
        fmt.Println("status code:", do.StatusCode)
        // return nil
    }
    b := make([]byte, 1000)
    n, err := do.Body.Read(b)
    if err != nil && err != io.EOF {
        fmt.Println("readbody", err)
        return &Qrstatus, err
    }
    do.Body.Close()
    if do.StatusCode != 200 {
        fmt.Println("httperrmsg", string(b))
        return &Qrstatus, err
    }
    err = json.Unmarshal(b[:n], &Qrstatus)
    if err != nil {
        fmt.Println(err)
        return &Qrstatus, err
    }
    Qrstatus.appkey = r.appkey
    if str := Qrstatus.sha1(); str != "" {
        return &Qrstatus, errors.New(str)
    }
    return &Qrstatus, nil
}

type RealtimeReturn struct {
    ReturnBase
    Eventid string `json:"event_id"`
}

func (r *RealtimeReturn) sha1() string{
    src := make(map[string]string)
    src["status"] = string(strconv.Itoa(r.Status))
    src["description"] = r.Description
    src["event_id"] = r.Eventid
    var keys []string
    for k, _ := range src {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    var data string
    for _, k := range keys {
        l := k + "=" + src[k]
        data += l
    }
    s := sha1.New()
    io.WriteString(s,data+r.appkey)
    sig := fmt.Sprintf("%x",s.Sum(nil))
    if sig != r.Signature {
        return r.Description
    }
    return ""
}
