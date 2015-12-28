package main

import (
    "fmt"
    "Secken-Server-SDK-For-Go/pcloud"
)

func main () {
    qrurl := pcloud.NewQrcodeForAuth("IXgdZ1A7CFUej2ytUbVjFJKS5ICiorw4","ELD0DNzMYep7m6Uo1v3v","","","","")
    qr, err := qrurl.Get()
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(qr.GetQrcodeUrl())
    rla := pcloud.NewRealtimeAuthorization("IXgdZ1A7CFUej2ytUbVjFJKS5ICiorw4","ELD0DNzMYep7m6Uo1v3v","secken","","","","")
    rrla, err := rla.Post()
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(rrla)
    at := pcloud.NewQueryAuthToken("IXgdZ1A7CFUej2ytUbVjFJKS5ICiorw4","ELD0DNzMYep7m6Uo1v3v","adfasdfqwecvasdfrqwesadfadgadfas")
    rat, err := at.Get()
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(rat)
    event := pcloud.NewEventResult("IXgdZ1A7CFUej2ytUbVjFJKS5ICiorw4","ELD0DNzMYep7m6Uo1v3v",rrla.Eventid)
    rev, err := event.Get()
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(rev)
}
