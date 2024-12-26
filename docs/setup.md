# Lab ortamını kurmak
Makinenizde hali hazırda bir KVM/QEMU sanallaştırma ortamınız olduğunu varsayıyor
olacağım, ancak yoksa, distronuzdaki `qemu` ve `libvirt` paketlerini kurarak bunu yapabilirsiniz.

Şimdi lab dosya sistemine ve bir kernele ihtiyacınız var.

### Hazır arşiv
Aşağıdaki arşivde hazır bir dosya sistemi ve de kernel binarysi bulabilirsiniz:

- [o101.tar.gz](https://files.ngn.tf/p/o101.tar.gz) (1.7G - Arşivden çıkarınca 6GB)
- **PGP imzası**: [o101.tar.gz.sig](https://files.ngn.tf/p/o101.tar.gz.sig)
- **SHA256 imzası**: `1712ab2a1b67312a26d60f55798da385c0e7b4b3c7823f2b329eb428fee3aabc`

İndirdikten ve de doğruladıktan sonra, `dist` isimli bir dizin oluşturup, arşivi içine taşıyın
ve çıkartın:
```bash
mkdir -pv dist
mv o101.tar.gz dist
cd dist
tar xvf o101.tar.gz
```

### Kaynaktan derlemek
Root dosya sistemini oluşturmak için `debootstrap` aracını kurduktan sonra, kaynak dizininde `make` çalıştırarak
dosya sistemini oluşturabilirsiniz. Kernel'i derlemek adına kendiniz manual olarak derleme yapabilirsiniz,
ya da yazdığım küçük bir otomasyon scripti olan [kbuild](https://github.com/ngn13/kbuild) aracını kullanabilirsiniz.

### Sistemi başlatmak
Root sistem ve de kernel hazır ise `make qemu` ile QEMU/KVM sistemini başlatabilirsiniz. Eğer 2GB'dan daha az
serbest RAM'iniz varsa, sizi uyarıyım, makine çok yavaş olacaktır ancak [scripts/qemu.sh](../scripts/qemu.sh)
scripti editleyip 2GB'den daha az RAM kullanabilirsiniz.

Sistem açılınca **kullanıcı adı olarak** `root` ve **parola olarak** `o101root` ile giriş yapabilirsiniz,
ancak daha stabil bir shell istiyorsanız aynı kullanıcı ve parola ile port 2222'de SSH'a bağlanın:
```bash
ssh root@127.0.0.1 -p 2222
```
Benim önerim SSH'ı kullanmanız olacaktır.

Sisteme girdikten sonra ev dizininde (`/root`), tüm yapıcağımız pratiklere erişebilirsiniz.
Her pratik için `Makefile` programı derlemek için gerekli komutları içerirken, `.c` dosyaları
programın kaynak kodunu içerir.

Bir pratiği derlemek için `make` komutunu kullanabilirsiniz. Bu `Makefile`da belirtilen şekilde
kaynak dosyalarını derleyip, pratiğin adı ile aynı isme sahip bir `.elf` programı oluşturacaktır.

Ve evet makinede `vim` editörü ve `tmux` çoklu pencere yöneticisi ile beraber exploitinizi
derlemek için gerekli olacak temel araçlar mevcut. Yani onları indirmek ile uğraşmak zorunda değilsiniz.

Yine de birşey indirmek isterseniz, Debian GNU/Linux dağıtımının `apt` paket yöneticisini kullanabilirsiniz:
```bash
apt install <paket adı>
```
Daha fazla bilgi için [bu manual sayfasına](https://www.debian.org/doc/manuals/debian-faq/pkgtools.en.html) göz atın.

# Başlamadan önce...
İlk pratiğe geçmeden önce hemen birkaç şeyden bahsetmek istiyorum. İlk olarak tüm pratiklerin çözümleri,
[`src/solves`](../src/solves/) dizini altında bulunuyor. Bu çözüm scriptleri makineye dahil değil, bunun sebebi
exploitleri bu rehberi takip ederek kendiniz sıfırdan oluşturmanızı istemem. Bu sayede benimle beraber kendi exploitlerinizi
yazarak herşeyi temel olarak anlayabilirsiniz.

Ayrıca rehberler içinde verilen kod parçalarını doğrudan kullanmayınız. **Özellikle dinamik olarak hesaplanan adresler eski
olabileceğinden doğrudan çalışmıyacaktır.** Adresleri rehberde gösterilen şekilde kendiniz hesaplamanız gerekecektir.

---
[Önceki](README.md) | [Sıradaki](0x0.md)
