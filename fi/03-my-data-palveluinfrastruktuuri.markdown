![Olennaista on, että kontrolli omaan dataan on yksilöillä itsellään, ja että infrastruktuuripalveluiden tarjoajia on useita ja että palvelut ovat yhteentoimivia ja vaihdettavissa.][image-chapter-3]

# 3. My Data -palveluinfrastruktuuri

Tässä luvussa esitellään erilaisia organisoitumistapoja, jotka mahdollistavat henkilötiedon yhdistämisen eri lähteistä. Organisoitumistapa vaikuttaa siihen, kuinka helposti hyödynnettävää henkilötieto on, kuinka läpinäkyvää tiedon käyttö on, kuinka hyvin rakenteet tukevat avointa kilpailua ja yhteiskehittämistä sekä kuinka ihmiskeskeistä ja yksilöä tukevaa henkilötiedon hyödyntäminen tulevaisuudessa on.

Hahmoteltu avoin My Data -infrastruktuuri on näkemys siitä, mitä teknisiä ja organisatorisia perusratkaisuja tarvitaan, jotta My Datan periaatteet voisivat toteutua. My Data -infrastruktuuri on palvelu- ja tietoinfrastruktuuria, mutta yksinkertaisuuden vuoksi nimitämme sitä myös pelkästään infrastruktuuriksi.

Tavoitteena on luoda luotettava ja pelkistetty infrastruktuuri, joka on avoin uusille toimijoille ja uusille innovaatioille. Ihmisille tämä tarkoittaa, että on olemassa helppokäyttöisiä infrastruktuuripalveluita kuten henkilötietoasetusten etähallinnointipalveluita, My Datan säilytyspalveluita ja omien profiilien ylläpitopalveluita. Nämä palvelut ovat paloittain laajennettavissa, ja palveluja voi helposti vaihtaa, koska data liikkuu niiden välillä My Data -rajapintojen ja operaattorien välisen yhteentoimivuuden ansiosta. Infrastruktuurin ominaisuuksien on taattava ihmisille muun muassa mahdollisuus suojata ja poistaa omaa tietoaan.

Kuka tai ketkä tarjoavat hallinnointipalveluita, ja pitäisikö näitä keskeisten infrastruktuuripalveluiden tuottajia valvoa tai säännellä kuten esim. pankkeja ja teleoperaattoreita säännellään nykyään? Muutaman miljoonan kuluttajan rikkaan profiilin hallinnointi on liiketoiminnallinen mahdollisuus, joka houkuttelee monia. Kukapa ei haluaisi olla koko kehittyvän toimialan keskiössä? Sääntelyä voidaan kehittää ajan myötä, mutta nyt alkuvaiheessa on syytä keskittyä luomaan infrastruktuurin pohja niin, ettei sinne synny perustavanlaatuisia valuvikoja, jotka myöhemmin haittaisivat tai estäisivät My Data -periaatteiden toteutumisen. Olennaista on, että kontrolli omaan dataan on yksilöillä itsellään, infrastruktuuripalveluiden tarjoajia on useita ja palvelut ovat yhteentoimivia ja vaihdettavissa.

## 3.1 Henkilötiedon organisointitapoja

Ennen kuin lähdetään tutkimaan, kuvaamaan ja kehittämään My Data -infrastruktuuria, on syytä kysyä, tarvitaanko infrastruktuuria ylipäänsä. Edellisissä luvuissa on kuvailtu My Data -rajapintoja ja sovelluksia. Eikö olisi helpompaa, jos nämä rajapinnat ja sovellukset keskustelisivat suoraan keskenään ilman välissä olevaa infraa? Nykykehitys onkin jo monin paikoin kehittymässä tällaisen orgaanisesti laajentuvan infrastruktuurittoman niin sanotun API-ekosysteemin suuntaan. Toisaalla taas syntyy yksittäisiä sektorikohtaisia aggregaattoreita, jotka pyrkivät keskittämään ja harmonisoimaan henkilötietoa omaan palveluunsa.

Vaihtoehtoisia henkilötiedon organisointitapoja on:

* **Infrastruktuuriton API-ekosysteemi**, jossa yksilö hallinnoi palveluiden yhdistymistä jokaisen palvelun sisällä erikseen (esimerkkinä nykyisten verkkopalveluiden APIt)

* **Organisaatiokeskeinen aggregaattorimalli**, jossa yksi organisaatio ottaa keskeisen roolin tiedon integraattorina (esimerkkinä Googlen ja Applen suljetut ekosysteemit tai aggregaattorit Taltioni<sup>[8]</sup> tai Mydex<sup>[9]</sup>) 

[8]: http://taltioni.fi/
[9]: https://mydex.org/

* **Avoin My Data -palveluinfrastruktuuri**, jossa henkilötiedon hallinta voidaan hajauttaa useamman keskenään yhteentoimivan operaattorin palveluun

* **Kansalliset järjestelmät**, jossa rakennetaan yksi alusta ja jonka operoinnissa julkishallinto ottaa keskeisen roolin henkilötiedon kerääjänä, jakelijana ja hyödyntämisen mahdollistajana (esim. kansalaistili, palveluväylä tai Viron X-road)

Nykykehityksessä näkyy viitteitä useista eri organisointitavoista, jotka tulevaisuudessa eivät välttämättä sulje pois toisiaan. Esimerkiksi on olemassa useita toimijoita, jotka pyrkivät toteuttamaan normaalia aggregaattorimallia avoimempaa mallia (kuten The Gooddata<sup>[10]</sup>, Respect Network<sup>[11]</sup>), mutta My Data -infrastruktuurin puuttuessa pyrkivät asettumaan itse keskeiseen asemaan, eivätkä näin toteuta vaihdettavuuden periaatetta. Kuva 3.1 visualisoi kolmen keskeisen mallin eroja. Seuraavissa kappaleissa analysoidaan näitä malleja laajemmin.

[10]: https://thegooddata.org/
[11]: https://www.respectnetwork.com/

![image alt text][image-3-1]

*Kuva 3.1: Erilaisia henkilötiedon yhdistämisen mahdollistavia organisointitapoja: vasemmalla infrastruktuuriton API-ekosysteemi, jossa kaikki datalähteiden ja sovellusten suhteet määritellään erikseen datalähteiden yksityisyysasetuksista, keskellä aggregaattorimalli, jossa yksittäinen toimija kerää ja harmonisoi dataa useasta lähteestä ja jakelee eteenpäin, oikealla avoin My Data -infrastruktuuri, jossa välittäjäorganisaatioita voi olla useita ja ne ovat kaikki yksilön palveluksessa. Huom. kuvassa viivat voivat kuvata datan liikkumista tai luottamussuhdetta. Osa datasta on käytännöllistä kerätä yhteen (datapankki), mutta osa tallennetaan syntypaikassa ja välittäjäorganisaatio ainoastaan huolehtii käyttöluvista (dataoperaattori). Tarpeettomien datakopioiden tekemistä pyritään välttämään.*

### 3.1.1 Infrastruktuuriton API-ekosysteemi

Rajapintojen laajasti yleistyessä voidaan puhua API-ekosysteemistä, missä uusia yhteyksiä eri palveluiden välille voidaan luoda nopeasti ja ketterästi ilman erillisiä taustalla olevien organisaatioiden kahdenvälisiä sopimuksia. Esimerkiksi REST<sup>[12]</sup> (RESTful API) on tapa tehdä rajapintoja, joka on yleistynyt nopeasti, ja sen toteuttamiseen ja hyödyntämiseen on paljon toteutustekniikoita ja oppeja, vaikka lähestymisen takana ei olekaan yksittäistä merkittävää edistäjäorganisaatiota. RESTin yleistyminen on esimerkki API-ekosysteemin itseohjautuvuudesta ja ketteryydestä. Yleisesti voidaan sanoa, että API-ekosysteemi edistää tiedon virtaamista, luo uutta liiketoimintaa ja on hyödyllinen edistysaskel digitaalisten palveluiden kehityksessä.

[12]: http://en.wikipedia.org/wiki/Representational_state_transfer

Nykyisellään rajapintojen ominaisuudet vaihtelevat merkittävästi. Kunkin palvelun toteuttaja voi vapaasti määrätä API:n protokollan ja ominaisuudet. Yleensä API:n kehittämisen motiivi on tehdä omasta palvelusta mahdollisimman keskeinen osa laajempaa palvelukokonaisuutta ja nähdä API:a hyödyntävät muut palvelut oman palvelun laajennuksina. Kun yksittäiset API:t on toteutettu palveluntarjoajan omien motiivien mukaisesti, usean palveluntarjoajan API:en yhdistämisestä muodostuu haastava kokonaisuus. Rajapintojen tekninen yhdisteltävyys varmasti paranee ajan myötä, kun syntyy yhteisiä rajapintastandardeja.

Henkilötiedon hallittavuuden ja ihmiskeskeisyyden kannalta infrastruktuurittoman API-ekosysteemin ongelma on palveluiden ja niiden välisten yhteyksien suuri määrä. Kun palvelujen välisten yhteyksien määrä kasvaa, niiden ylläpidettävyys monimutkaistuu. Yksilölle ei enää muodostu kokonaiskuvaa oman tietonsa sijainnista ja tiedon liikkumisesta palvelujen välillä, ja yleensäkin käyttäjien mahdollisuus hallita ja hyödyntää tietoa on heikko.

Infrastruktuurittomassa systeemissä ainoa tapa hallita, mitä tietoa mistäkin palvelusta menee muihin, on kirjautua jokaiseen palveluun erikseen, ja etsiä se paikka, jossa näytetään, mille kaikille muille palveluille on myönnetty lupa rajapinnan kautta lukea käyttäjän dataa. Nykyisin verkkoaktiivisella kuluttajalla on käytössään ehkä parikymmentä palvelua, jotka voivat rajapintojen kautta kytkeytyä muihin palveluihin. Näitä ovat esimerkiksi sosiaalisen median palvelut, monet mobiilisovellukset ja internetiin kytketyt elektroniset laitteet kuten digivaa’at ja aktiivisuusmittarit. Muutaman palvelun erillinen hallinta on vielä mahdollista, mutta erilaisen henkilökohtaisen ja kotiin liittyvän anturiteknologian yleistymisen myötä hallittavia datalähteitä voi tulevaisuudessa olla kymmenien sijaan satoja tai tuhansia, ja silloin tiedonhallintaa helpottavan infrastuktuurin tarve on jo ilmeinen.

### 3.1.2 Organisaatiokeskeinen aggregaattorimalli

Tällä hetkellä valtaosa henkilötiedosta sijaitsee organisaatioiden hallinnoimissa tietokannoissa ja tiedon käyttö tapahtuu yksilöille läpinäkymättömällä tavalla. Tästä hyvänä esimerkkinä ovat vaikka kansainväliset verkkomainonnan yritykset ja niiden väliset verkostot. Monelle organisaatiolle henkilötieto, asiakkuudet ja profiilit ovat kauppatavaraa. Myös julkisella sektorilla henkilötietoja yhdistetään valtaosin organisaatioiden välisiin sopimuksiin perustuvina yksittäisinä järjestelmäintegraatioina.

Kun meillä ei vielä ole avoimiin standardeihin perustuvaa henkilötiedon yhteentoimivuutta, niin yksittäiset globaalisti toimivat yritykset laajentavat kukin omaa henkilötiedon ekosysteemiään ja pyrkivät suuren käyttäjävolyymin voimalla de facto -standardin asemaan. Liian pitkälle vietynä tässä kehityskulussa on riski, että muiden pelureiden tulo markkinoille estyy tai ne joutuvat alihankkijan asemaan ilman valinnan tai vaikuttamisen mahdollisuuksia.

Viimeisien vuosina eri sektoreilla on alkanut tapahtua kehitystä, joka mahdollistaa useiden toimijoiden keräämän tiedon yhteiskäyttöä. Terveyssektorilla tästä useita esimerkkejä eri maissa, kuten sveitsiläinen Healthbank<sup>[13]</sup>, brittiläinen Patients Know Best<sup>[14]</sup> ja suomalainen Taltioni. Tällaisessa rakenteessa yritykset perustavat yhteisen palvelun, josta tulee tiedon välittämisen keskipiste. Keskittäminen edistää tiedon yhdistämistä ja uusien käyttötapojen kehittämistä, mutta samalla järjestelmä tulee riippuvaiseksi yksittäisestä toimijasta, joka päättää toiminnan tavoitteista ja tekemisen tavoista.

[13]: http://healthbank.ch/
[14]: http://www.patientsknowbest.com/
 
### 3.1.3 Avoin My Data -palveluinfrastruktuuri

My Data -lähestyminen eroaa rajapintaekosysteemistä siinä, että ihmisillä on suora hallinta tiedon välitykseen yleiskäyttöisten infrastruktuuripalvelujen avulla. Tieto virtaa infrastruktuurin välittämänä keskitetymmin (tämä on eri asia kuin keskitetysti, mikä ei ole tavoiteltavaa), mikä helpottaa ja tehostaa hallintaa ja luo paremmat edellytykset sovellusten kehittämiselle.

Toisin kuin aggregaattorimallissa My Data -mallissa on kuitenkin useita kilpailevia infrastruktuuripalveluita, jotka toimivat yhteen avoimuuden ja standardoinnin ansiosta. Ihminen voi valita itselleen sopivimmat palvelut muun muassa tiedon tallennukseen ja useiden datalähteiden keskitettyyn hallinnointiin. Hallintapalvelut voivat tulla usealta toimittajalta tarpeiden mukaan. Malli muistuttaa tapaa, jolla rahavirtoja hallitaan nykypäivänä. Kaikki käyttävät samaa rahaa, eri toimijoiden välillä on yhteistoiminnan periaatteita, ja pankin vaihtaminen onnistuu verrattain helposti. Seuraavaksi käsitellään keskeiset My Data -infrastruktuuripalvelut ja niin sanottu operaattorimalli.

## 3.2 Infrastruktuuripalveluita

Infrastruktuuripalveluilla tarkoitetaan sellaisia peruspalveluita, jotka mahdollistavat toisaalta yksilön kontrollin omaan dataansa ja toisaalta helpottavat yksittäisten My data -sovellusten toteuttamista, kun jokaisen sovelluksen kehittäjän ei tarvitse erikseen toteuttaa samoja ominaisuuksia omaan palveluunsa. Infrastruktuuripalveluita ovat muun muassa hallintapalvelut, tallennuspalvelut ja autentikaatiopalvelut.

### 3.2.1 Hallintapalvelut

Hallintapalvelu on keskeinen osa My Data -infrastruktuuria. Hallintapalvelu on paikka, missä My Data -rajapinnat, datan varastointi, sovellusten jatkohyödyntäminen, yksilöiden oma datan hyödyntäminen ja datan anonymisointi kohtaavat.

Edistyneissä hallintapalvelussa tulisi olla seuraavanlaisia ominaisuuksia:

* Rajapintoihin liittyminen ja tarvittava autentikaatio

* Yksityisyysasetusten etähallinta

* Henkilötiedon tallennus yksilön niin halutessa (ks. tallennuspalvelut)

* Tiedolle tehtävät operaatiot ja mahdollisuus operoida paikallisia sovelluksia

* Tiedon jakelu anonymisointia ja sitä seuraavaa julkistamista varten

Hallintapalvelun hyvä toiminnallisuus vaatii ylläpitäjältä suhteellisen laajaa palvelupakettia. On epärealistista, että jokainen henkilötietoa hyödyntävä taho voisi toteuttaa kaikki listatut ominaisuudet. Hallintapalvelun toiminnan analogiana voisi käyttää sähköpostijärjestelmän toimintaa. Saman sähköpostitilin sähköposteja voidaan vastaanottaa ja lähettää usealla eri ohjelmalla, ja tiettyjen ohjelmien avulla voidaan hallinnoida useita sähköpostitilejä.

### 3.2.2 Tallennuspalvelut

My Data -lähestymisessä keskeistä on henkilötiedon hallinnan organisoiminen. Yksilön luvalla tieto voi virrata suoraan palvelusta toiseen ilman, että sitä tallennetaan välillä. Tällaisia palvelujen välisiä kytköksiä hallinnoidaan edellä esitellyllä hallintapalvelulla. On kuitenkin useita syitä, miksi yksilö voi haluta tallettaa ja arkistoida tietoa itselleen, tätä varten tarvitaan tallennuspalveluja.

My Data -infrastruktuurissa voi olla erilaisia tallennuspalveluita. Näitä voidaan kutsua tileiksi lainaten metaforaa, joka on tuttu pankkitileistä, sähköpostitileistä ja asiakastileistä. My Data -tilien ominaisuuksia on esitelty alla olevassa listassa.

* My Data -tileille voi kerätä ja tallettaa omat tiedot erilaisista henkilötietorajapinnoista.

* My Data -tilejä voi olla useita, osa tileistä voi olla usean henkilön yhteisiä ja osa voi olla pseudonyymitilejä.

* Tileillä on erilaisia autentikaatiotasoja.

* Tilin hallintaohjelma pitää automaattisesti rekisteriä siitä, mitä tietoa on luovutettu eteenpäin, ja osaa hallita tiedon eteenpäin luovuttamista.

* Tilin yhteydessä voi ajaa erilaisia sovelluksia datan muokkaamiseen, kuvaamiseen ja analysointiin.

* Tilin yhteydessä voi olla dataa jalostavia toimintoja, jotka voivat tuottaa esimerkiksi profilointeja datasta ilman raakadatan eteenpäin luovutusta.

* Tilejä voi linkittää toisiinsa ja niitä voi hallinnoida suoraan tai erillisen My Data -hallintapalvelun avulla. Osa tileistä voi sijaita kotikoneella, osa palveluntarjoajan huomassa.

* Tili voi olla kryptattu datavarasto, jolloin tallennuspalvelun tuottajalla ei ole pääsyä informaatiosisältöön.

<table>
  <tr>
    <td><b>Paikalliset ja siirrettävät sovellukset</b>

Paikallisilla sovelluksilla tarkoitetaan ohjelmia, jotka eivät lähetä käyttäjän dataa eteenpäin toiselle verkkopalvelimelle vaan toimivat siten, että sovellus tai dataa analysoiva koodi ladataan verkosta datan luo.

Paikalliset sovellukset voivat toimia käyttäjän päätelaitteella tai käyttäjän palvelimella tai, mikäli data on säilössä, jossain pilvipalvelussa. Silloin paikallisuudella tarkoitetaan, että sovelluksen ajoympäristö on datatilin yhteydessä. Olennaista on, ettei käyttäjän dataa tarvitse siirtää sieltä, missä se oli alunperin.

Paikallisten sovellusten toimintalogiikka on siis käänteinen verrattuna sovelluksiin, joiden luo data lähetetään. Useimmiten paikallista sovellusta käytetään selaimella kuten mitä tahansa verkkosovellusta, eikä käyttökokemus eroa perinteisestä verkkopalvelimilla toimivista palveluista ja sovelluksista.

Kun datan määrä on suuri, niin on käytännöllisempää tuoda ohjelmakoodi datan luokse. Päätelaitteiden ja selaimien ominaisuudet ovat kehittyneet niin paljon, että moni toiminnallisuus, jonka toteuttaminen aiemmin oli mahdollista vain palvelimella, voidaan nykyisin tehdä päätelaitteessa.

Unhosted https://unhosted.org/
OwnCloud https://owncloud.org/</td>
  </tr>
</table>


### 3.2.3 Autentikaatio- ja luottamuspalvelut

My Data -infrastruktuurissa on monenlaisia autentikaatiotarpeita. Ihmisten ja heidän My Data -tilien autentikoimisen lisäksi myös data ja palvelut pitää pystyä autentikoimaan. Kun ihminen operaattorin kautta välittää dataa eteenpäin, niin vastaanottavan palvelun pitää tietää, onko data todella sitä, mitä sen väitetään olevan, vai onko sitä muuteltu matkalla. Esimerkiksi tulevaisuuden rekrytointipalvelu ottaa vastaan datana opiskeluhistorian ja haluaa vahvistuksen tiedon oikeellisuudesta. Vastaavasti ihmisten oikeusturvan kannalta on merkityksellistä, että teknisesti voidaan varmistaa, etteivät erilaiset palvelut vääristele ihmisten dataa heidän tietämättään.

Teknologian kehitys saattaa tuoda ratkaisun siihenkin, miten voidaan todistaa toisaalla syntyneen datan autenttisuus myöhemmin ja eri käyttökontekstissa. Proof of existence<sup>[15]</sup> -verkkopalvelu on konseptiehdotus siitä, miten Bitcoin-kryptovaluutan pohjalla olevaa teknologiaa voidaan hyödyntää aikaleimaamaan dokumentti niin, että myöhemmin voidaan tarkistaa bitin tarkkuudella, onko dokumentti sama vai onko sitä peukaloitu matkalla. Dokumentista lasketaan kryptografinen sormenjälki, joka tallennetaan hajautetusti verkkoon. Jos dokumentti on bitilleen sama kuin alkuperäinen, niin myöhemmin uudelleen laskettuna sormenjälki täsmää, mutta jos pilkkuakin on muutettu, niin muutos paljastuu, koska sormenjälki ei enää täsmää.

[15]: http://www.proofofexistence.com/

Sähköinen luotettava identiteetti on tärkeä mahdollistaja kansalaiselle ja  organisaatioille. Mikäli luottamus toisen osapuolen sähköisen agentin autenttisuuteen puuttuu, mitään tietoa ei uskalleta antaa My Data -rajapintojen kautta. Autentikaatio ja luottamuspalvelut ovat keskeinen osa My Data -infrastruktuuria. Osin My Data -tilien ja oikeuksienhallintaprotokollan pitää ottaa huomioon tietoturva ja autentikaatiokysymykset jo standardin tasolla, mutta tärkeää olisi, että järjestelmä mahdollistaisi luottamuspalvelujen rakentamisen perustan päälle. On mahdollista, että toiset haluavat enemmän joustavuutta, vaikka se tarkoittaisi tietoturvan tasosta tinkimistä, ja toisille taas on ehdottoman tärkeää saada maksimaalinen tietoturva.

### 3.2.4 Anonymisointipalvelut

My Datan hyödyntäminen perustuu usein mahdollisuuteen yhdistellä eri lähteistä peräisin olevaa henkilötietoa. Tämä vaatii, että tieto yhdistyy siihen liittyvään ihmiseen. Monien käytännön sovellusten kannalta olisi kuitenkin tärkeää, jos yksilö voisi käyttää omaa autenttista dataansa eri yhteyksissä ilmiantamatta omaa identiteettiään. Anonymisoinnin tarve tulee yleisimmin vastaan, kun tehdään populaatiotason tutkimusta. Tutkijat ja data-analyytikot haluaisivat hyödyntää ja yhdistellä laajoja datamassoja, mutta heitä ei käytännössä kiinnosta yksittäinen yksilö. Jotta mahdollistetaan laajat big data -tutkimukset ja tutkimusaineistojen yhdistäminen yksilön tietosuojaa heikentämättä, My Data -infrastruktuurissa on oltava luotettavia anonymisointipalveluita, jotka mahdollistavat data yhdistämisen ja anonymisoinnin tutkimustarpeisiin.

Erilaisten de-anonymisointitekniikoiden kehitys ja lisääntyneet mahdollisuudet yhdistää dataa useista lähteistä ovat siirtämässä ja hämärtämässä rajoja yksilöivän henkilötiedon ja anonyymin tiedon välillä. Tämä on johtanut kiivaaseen keskusteluun, jossa toiset hyvin perustein väittävät, ettei aukoton anonymisointi ylipäätään ole mahdollista, ja että kaikkea alunperin yksilöihin liittyvää tietoa pitää käsitellä henkilötietona lain säätämällä tavalla. Toiset taas väittävät yhtä lailla hyvin perustein, että näin tiukka tulkinta rajoittaisi monia nimettömien tietojen käyttötapoja, joissa hyödyt ovat selvästi suurempia kuin yksityisyyden suojan menetyksestä aiheutuvat haitat. Anonymisointipalvelujen toteuttaminen on teknisesti ja sosiaalisesti haaste. Todelliset hyödyt syntyvät, kun palvelulla on käytössä kymmenien tai satojen tuhansien ihmisten dataa. Kun tähän kokoluokkaan päästään, voidaan alkaa tehdä tiedettä ja älykkääseen hallintoon liittyvää tutkimusta ennen näkemättömällä tasolla.

<table>
  <tr>
    <td><b>My Data ja big data</b>

Big datalla viitataan äärimmäiseen suureen ja nopeasti karttuvaa tiedon määrään, jonka kerääminen, tallennus ja analyysi vaativat uusia käsittelymenetelmiä. Toisaalta big datan voi käsittää myös tiedon paradigman muutoksena. Sen myötä yrityksissä ja hallinnossa voidaan yhä useammin tehdä päätöksiä, jotka perustuvat suoraan kerättyyn ja mitattuun tietoon. Tutkimuksessa on mahdollista muodostaa teoriaa uusilla tavoilla, kun datamassojen analysointi ja yhdistely on entistä helpompaa. Laajojen datamassojen sovellusmahdollisuudet ovat lähes rajattomat ja tiedon hyödyntämisestä on tullut yhä vahvemmin kilpailukyvyn edellytys alasta riippumatta. (LVM 2014) 

Suuria datamääriä syntyy mm. internettiin kytketyistä laitteista, anturijärjestelmistä, sosiaalisesta mediasta, verkon yli tehtävistä transaktioista, yritysten liiketoimintaan liittyvistä ohjaus- ja raportointijärjestelmistä jne. Keskeinen osa big datasta on ihmisten käyttäytymisdataa, joka perustuu asiakkaan tunnistamiseen. Big data -keskustelussa korostetaan henkilötietojen analysoinnin ja hyödyntämisen mahdollisuuksia organisaatioiden näkökulmasta. Ihmisten näkökulma on supistettu usein vain vaatimukseen siitä, että yksityisyydensuoja säilytetään. Asiakkaan kiinnostusta saati oikeutta omiin tietoihinsa ei big data -keskustelussa ole juurikaan tuotu esille. 

Henkilöihin liittyvässä tiedossa My Data ja big data ovat kaksi toisiaan täydentävää näkökulmaa, "ihmisnäkökulma" ja "yritysnäkökulma". My Data tuo läpinäkyvyyttä ja sitä kautta hyväksyttävyyttä henkilöihin liittyvien datamassojen käsittelyyn ja antaa konkreettisia keinoja yksityisyydensuojan toteuttamiseen. Ilman tätä ihmisnäkökulmaa monet big datan hyödyntämismahdollisuudet katoavat, koska ne eivät ole yksilöiden suojan kannalta hyväksyttäviä.</td>
  </tr>
</table>


## 3.3 My Data -operaattori

On lähes välttämätöntä, että infrastruktuurilla on jonkinlaisia välittäjäorganisaatioiden roolissa olevia toimijoita, jotka muun muassa ylläpitävät ja kehittävät edellä esitettyjä keskeisiä peruspalveluita. Tällaisista organisaatioista käytetään yleisnimitystä My data -operaattori. Muissa yhteyksissä käytetään nimitystä datapankki, databroker tai data-aggregaattori kuvaamaan samanlaista tai osin samanlaista toimijaa. Tässä raportissa tarkoitamme My Data -operaattorilla yksilön infrastruktuuripalveluita ylläpitävää organisaatiota. Operaattori ylläpitää 'My Data -tilejä', joilla henkilötietojen käyttöön liittyviä oikeuksia hallitaan. Tilin hoitoon voi kuulua tiedon varastointia tai välittämistä.

Operaattorimalli perustuu luottamukseen ihmisten ja operaattoriorganisaatioiden välillä. Koska henkilötiedon kontrolli halutaan säilyttää yksilöillä itsellään, tarkoittaa se, että My Data -operaattorien tulisi olla ihmisten eikä yritysten palveluksessa. Jokaisella voisi olla luotettuja My Data -operaattoreita eri luonteisille tiedoilleen: terveystiedot, omaisuustiedot, kuluttajaprofiilitiedot, liikkumisprofiilitiedot jne. Yksilöt antavat datan välittämiseen, jalostamiseen ja säilyttämiseen liittyviä tehtäviä näille operaraattoreille, koska eivät halua ylläpitää omia datavarastoja kotikoneellaan, vaikka se teknisesti olisi mahdollista. Halutessaan ihminen voisi hallita kaikkia tietojaan myös vain yhden operaattorin kautta.

Operaattorimalli toimii myös sovellustason kilpailun mahdollistajana. Sovelluskehittäjille operaattorit tarjoavat riittävän suuren asiakaspotentiaalin ja yhtenevän sovellusintegraatiopisteen, mutta yksilöitä palvelevilla operaattoreilla ei kuitenkaan ole intressiä sulkea markkinoita esimerkiksi tukemalla vain tiettyjä yksittäisiä sovelluksia.

Kypsän My Data -infrastruktuurin toteuttajina ja hyödyntäjinä voi olla lukuisia osin keskenään kilpailevia ja osin toistensa toimintaa täydentäviä operaattoreita. Operaattorin organisoitumismalli vaikuttaa siihen, minkälaisella arvoketjulla se rakentaa omaa (liike)toimintaansa ja minkälainen investointikyky ja motivaatio sillä on. Seuraavassa esimerkkejä operaattorin ansaintamalleista:

* Yksilö maksaa palvelusta (tilinhoitomaksu).

* Operaattori saa tuloja toimiessaan sovellusten jakelukanavana (jakelija).

* Operaattori saa tuloja välittäessän yksilön puolesta henkilötietoa (aggregaattori-operaattori).

* Operaattori tarjoaa lisäarvopalveluita (ensisijainen palveluntarjoaja).

Kun infrastruktuuri on vasta hahmottumassa, on tärkeää kiinnittää huomiota siihen, millaiset operaattorit saavat jalansijaa alkuvaiheessa, koska niiden toiminta vaikuttaa keskeisesti infrastruktuurin kehityssuuntaan. Seuraavaksi on listattu erilaisia operaattoreiden organisoitumiseen vaikuttavia ominaisuuksia:

* **Valtiollisesti lisensoitu operaattori –** Nykyisiin teleoperaattoreihin tai pankkeihin vertautuva malli, jossa valtiollinen taho myöntää operaattorille luvan tarjota yksilöille henkilötiedon hallintapalveluita, autentikaatiota ja mahdollisesti myös yrityksille ja organisaatioille datan varmentamista. Lisensointi ei ole rajoittunut operaattorin organisoitumismalliin, eli osuuskunta voi olla yhtälailla lisensin haltija kuin kaupallinen yrityskin.

* **Verkosto –** Vertaisperiaatteilla ilman operaattoria toimiva infrastruktuuri (p2p-pohjainen itseoperaattoreiden verkosto), joka nojautuu täysin teknologiaan. Liiketoimintarakenteiden kehittyessä myös vertaismalliin perustuville infrastruktuureille ilmaantuu usein operaattoreita, jotka tekevät vertaisverkon käytöstä yksinkertaisempaa ja helpompaa asiakkailleen. Näille järjestelmille on kuitenkin ominaista, että operaattoria ei ole pakko käyttää, vaan yksittäinen henkilö (vertainen) voi toimia myös itse omana operaattorinaan (rahan käyttö ilman pankkia vielä onnistunee, mutta matkapuheluita ei voi soittaa ilman operaattoria).

* **Yritysten yhteenliittymä –** Ryhmä yrityksiä (todennäköisesti henkilötiedon lähteitä ja hyödyntäjiä) perustaa yhteenliittymän ja käynnistää operaattoritoiminnan. Tästä hyvänä esimerkkinä on Taltioni.

* **Ihmisten yhteenliittymä –** Osuuskunnat, joissa ihmiset olisivat omistajia, voisivat olla myös My Datan hallinnointiin joissain tapauksissa sopiva malli. Yhteisten resurssien hoitoon perustettiin jo 1800-luvulla esim. vesi ja puhelinosuuskuntia. Esimerkiksi henkilötietoa käsittelevä  sveitsiläinen healthbank.ch on organisoinut toimintansa yksilöiden omistamaksi osuuskunnaksi.

* **Valtiollinen operaattori –** Esimerkiksi valtion hallinnoimat kansalaistili, KanTa, Ruotsin terveystili yms. ovat esimerkkejä valtiollisten operaattorien (yleensä jokin virasto) hallinnoimista järjestelmistä. Monet teleoperaattorit ovat alun perin käynnistyneet kansallisina toimijoina,mutta ne on yksityistetty liiketoimintakentän kilpailun ja kansainvälistymisen vuoksi.

* **Itsenäinen kaupallinen osakeyhtiö** – My Data -operaattori voi olla täysin kaupallisilla periaatteilla toimiva organisaatio. Tällaisen organisaation kasvun ja kansainvälistymisen edellytykset ovat tarjolla olevien rahoitusmallien takia mahdollisesti parhaat. Alkuvaiheessa täysin kaupallisilla interesseillä itsenäisesti toimiva taho voi olla hankalassa tilanteessa, koska osa avoimien standardien ominaisuuksista saattaa olla kompromissi pysyvän kilpailuedun tai liiketoiminnan suojaamisen kannalta. Osakeyhtiömalli toimiikin mahdollisesti paremmin, kun operaattorimalli on yleistetty ja markkinoiden muoto, yleisimmät liiketoimintamallit ja koko alkaa hahmottua. 

<table>
  <tr>
    <td><b>Eikö olisi yksinkertaisempaa, jos olisi vain yksi iso tietokanta?</b>

My Data -infrastruktuurin keskeisiin tavoitteisiin kuuluu henkilötiedon hallinnointi- ja hyödyntämispalvelujen organisointi yksinkertaisesti ja ihmiskeskeisesti. Operaattorimalli monimutkaistaa asioita. Ei olekaan enää yhtä pistettä, jonka kautta kaikki tieto yhdistyy, vaan on useita rinnakkain toimivia operaattoreita.

Tällaisen avoimen, tietojen ja palvelujen yhteentoimivaa vaihdettavuutta tukevan operaattorikentän synnyttämistä pidetään kovana urakkana. Miksi ei vain tyydyttäisi kansainvälisten, keskenään kilpailevien, mobiiliviestintää tai sosiaalisen median palveluita tarjoavien yhtiöiden walled-garden tyyppisiin ekosysteemeihin My Data -tiedon säilytys ja kehityspaikkoina - tai tavoiteltaisi yhtä, vaikkapa kansallista, toimijaa keskitetyksi operaattoriksi?

Keskeinen yhden organisaation malliin liittyvä ongelma on koko järjestelmän riippuvuus tästä yhdestä toimijasta (single point of failure). Kun on yksi taho, niin ongelmien syntyessä ne koskevat kaikkia, ja seuraukset voivat olla katastrofaalisia.

Useampi operaattori mahdollistaisi myös ketterän ja monipuolisen palvelukehityksen ja vaihtoehtoisten kilpailevien infrastruktuuripalveluiden rinnakkaisen kehittymisen. Toiset kaipaavat enemmän suojaa, kun taas toiset arvostavat järjestelmän keveyttä ja vapautta tehdä asioita itsenäisesti. Yhden organisaation malli saattaa helposti muuttua jäykäksi ja hitaaksi, eikä sovellu kevyiden käyttötapausten ketterään toteuttamiseen.

Kun olemme keskustelleet erilaisista henkilötiedon organisointitavoista kansainvälisissä kontekstissa, on tullut selväksi, että monessa muussa maassa kansalaisilla on huomattavasti vähemmän luottamusta hallintoon kuin Suomessa. Näissä maissa kansallisesti organisoitu tietojärjestelmä ei soveltuisi arkielämää ja yksilönvapauttaa korostavien sovellusten keskiöksi. On jopa poikkeuksellista, että Suomessa osa uskoo keskitetyn mallin mahdollisuuksiin. My Datan kannalta on keskeistä, että toimintamalleilla on mahdollisuus kansainvälisesti laajamittaiseen vaikuttavuuteen. Operaattorimalli on näin eri näkökantojen valossa arvioitu kestävimmäksi ja kansainvälisen yhteisen toimintatavan kannalta parhaaksi lähestymistavaksi.</td>
  </tr>
</table>

[image-cc-logo]: images/image-cc-logo.png
[image-okf-logo]: images/image-okf-logo.png
[image-0-1]: images/image-0-1.png
[image-0-2]: images/image-0-2.png
[image-0-3]: images/image-0-3.png
[image-0-4]: images/image-0-4.png
[image-1-1]: images/image-1-1.png
[image-1-1a]: images/image-1-1a.png
[image-1-1b]: images/image-1-1b.png
[image-1-1c]: images/image-1-1c.png
[image-2-1]: images/image-2-1.png
[image-2-info]: images/image-2-info.png
[image-2-2]: images/image-2-2.png
[image-2-3]: images/image-2-3.png
[image-2-4]: images/image-2-4.png
[image-2-5]: images/image-2-5.png
[image-3-1]: images/image-3-1.png
[image-4-1]: images/image-4-1.png
[image-4-3]: images/image-4-3.png
[image-chapter-0]: images/image-chapter-0.jpg
[image-chapter-1]: images/image-chapter-1.jpg
[image-chapter-2]: images/image-chapter-2.jpg
[image-chapter-3]: images/image-chapter-3.jpg
[image-chapter-4]: images/image-chapter-4.jpg
[image-chapter-5]: images/image-chapter-5.jpg
[image-chapter-6]: images/image-chapter-6.jpg
[image-cover]: images/image-cover.jpg
[image-back-cover]: images/image-back-cover.jpg