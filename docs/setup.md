# Lab ortamını kurmak 
Makinenizde hali hazırda bir KVM/QEMU sanallaştırma ortamınız olduğunu varsayıyor 
olacağım, ancak yoksa, distronuzdaki `qemu` ve `libvirt` paketlerini kurarak bunu yapabilirsiniz.

Şimdi lab dosya sistemine ve bir kernele ihtiyacınız var.

### Hazır arşiv
Aşağıdaki arşivde hazır bir dosya sistemi ve de kernel binarysi bulabilirsiniz:

- [o101.tar.gz](https://files.ngn.tf/p/k101.tar.gz) (1.7G - Arşivden çıkarınca 6GB)
- **PGP imzası**: [o101.tar.gz.sig](https://files.ngn.tf/p/o101.tar.gz.sig) 
- **SHA256 imzası**: `f287c43c975a072df01a719ee614cb4f2c2b0e80d1b8a00da5ec8d77a04b0631`

İndirdikten ve de doğruladıktan sonra arşivi `src` dizini altında çıkartabilirsiniz.

### Kaynaktan derlemek
Arch tabanlı dağıtımlarda root dosya sistemi `root.sh` scripti ile derlenebilir. Arch tabanlı
olmayan dağıtımlarda ise bu mümkün değil maalesef. Kernel'i derlemek adına kendiniz manual
olarak derleme yapabilirsiniz, ya da yazdığım küçük bir otomasyon scripti olan [kbuild](https://github.com/ngn13/kbuild)
aracını kullanabilirsiniz.

### Sistemi başlatmak
Root sistem ve de kernel hazır ise `./qemu.sh <bzImage dosyasının yolu>` formatında `./qemu.sh`
scripti ile QEMU/KVM sistemini başlatabilirsiniz.

Sistem açılınca **kullanıcı adı olarak** `root` ve **parola olarak** `o101root` ile giriş yapabilirsiniz,
ancak daha stabil bir shell istiyorsanız aynı kullanıcı ve parola ile port 2222'de SSH'a bağlanın:
```bash
ssh root@127.0.0.1 -p 2222
```
Benim önerim SSH'ı kullanmanız olacaktır.

Sisteme girdikten sonra ev dizininde (`/root`), tüm yapıcağımız pratiklere erişebilirsiniz. Bir
pratiği derlemek için `make` komutunu kullanın.

Ve evet makinede `vim` editörü ve `tmux` çoklu pencere yöneticisi ile beraber exploitinizi 
derlemek için gerekli olacak temel araçlar mevcut. Yani onları indirmek ile uğraşmak zorunda değilsiniz.

Yine de birşey indirmek isterseniz, Arch'ın `pacman` paket yöneticisini kullanabilirsiniz:
```bash
pacman -S <paket adı>
```
Daha fazla bilgi için [bu wiki sayfasına](https://wiki.archlinux.org/title/Pacman) göz atın.

---
[Önceki](README.md) | [Sıradaki](0x0.md)
