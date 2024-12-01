<h1 align="center">
  <img width="640px" src="assets/banner.png">
  </br>
  o101 | Bellek taşmalarını öğrenin
</h1>

o101, yani overflow 101 size bellek taşmalarını (memory overflow) öğretecek
ve pratik yapmanızı sağlayacak küçük bir rehber.

### Başlarken...
Mümkün olduğunca erkenden belirtmek isterim ki bu kaynak herkes için uygun
olmayabilir, biraz ön bilgiye ihtiyacınız olacak:

- **Zorunlu:** Bu kaynağı doğru şekilde kullanabilmek ve anlamak için aşağıdakilere ihtiyacınız olacak:
    * Temel GNU/Linux bilgisi
    * Genel bellek yönetimi (stack, heap vs) bilgisi
    * Temel assembly ve C bilgisi
    * Lab için QEMU/KVM kurulumu
    * GDB deneyimi ve bilgisi

- **Opsiyonel:** Bunun dışında aşağıdakileri biliyorsan bu kaynağı takip etmen çok daha kolay olur:
    * Az da olsa python bilgisi
    * tmux deneyimi

### Bir sorun mu var?
Eğer yardıma ihtiyaç duyarsanız, herhangi bir sorun yaşarsanız
bir [issue oluşturmaktan çekinmeyin](https://github.com/ngn13/o101/issues/new).

Ayrıca [doğrudan bana](mailto:ngn@ngn.tf) da ulaşabilirsiniz.

### Hazır mısın?
Herşey tamamsa, aşağıdaki linkleri kullanarak macerana başlayabilirsin.

İyi eğlenceler!

| Bölüm           | Açıklama                                                  | Link                        |
| --------------- | --------------------------------------------------------- | --------------------------- |
| Kurulum         | Pratik ortamını nasıl kuracağınızı öğrenin                | [setup.md](docs/setup.md)   |
| 0x0             | Dönüş adresi ile programın akışını değiştirin             | [0x0.md](docs/0x0.md)       |
| 0x1             | Stack üzerinde shellcode çalıştırın                       | [0x1.md](docs/0x1.md)       |
| 0x2             | ret2libc ve ROP ile NX bellek korumasını bypass edin      | [0x2.md](docs/0x2.md)       |
| 0x3             | Format metinleri ile stack çerezlerini leakleyin          | [0x3.md](docs/0x3.md)       |
| 0x4             | glibc'den adres leakleyerek ASLR kırın                    | [0x4.md](docs/0x4.md)       |
| 0x5             | ret2sys ile doğrudan sistem çağrılarını kullanın          | [0x5.md](docs/0x5.md)       |
