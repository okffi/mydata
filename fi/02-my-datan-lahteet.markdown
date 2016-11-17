![My Datan lähteet ovat käytännössä joko organisaatioiden tai yksilöiden itse keräämää henkilötietoa.][image-chapter-2]

# 2. My Datan lähteet

My Datan lähteet ovat käytännössä joko organisaatioiden tai yksilöiden itse keräämää henkilötietoa. Henkilötietoa syntyy nykyään valtavia määriä erilaisissa prosesseissa. Tässä luvussa esitellään yleiskatsaus siihen, miten henkilötietoa syntyy ja missä muodossa sitä on olemassa nykyisissä tietokannoissa.

Jotta organisaatioiden hallussa oleva henkilötieto muuttuisi My Dataksi, eli olisi helposti ja käytännöllisesti saatavilla ihmisille itselleen tulee datan lähteinä toimivissa palveluissa olla **koneluettava ohjelmointirajapinta**  (Application Programming Interface API), jonka mukaan eri ohjelmat voivat tehdä pyyntöjä ja vaihtaa tietoja keskenään. Rajapintojen kautta henkilötieto liikkuu vaivattomasti palvelusta toiseen. Parhaimmillaan samaa tietoa voidaan käyttää useissa sovelluksissa lähes reaaliaikaisesti. Henkilötiedon saatavuuteen liittyvistä rajapintojen ominaisuuksista koneluettavuus, standardien mukaisuus ja reaaliaikaisuus ovat tärkeimpiä, ja näistä on jo runsaasti hyviä esimerkkejä eri verkkopalveluissa.

My Data -periaatteista seuraa, että ohjelmointirajapinnalla pitäisi olla myös muita ominaisuuksia kuin henkilötiedon saatavuus rajapinnan kautta. Näistä keskeisimpiä ovat koneluettavat käyttöselosteet ja yksityisyysasetusten etähallinta, jotka yhdessä mahdollistavat **hallittavan ja standardoidun sopimisen**. Näiden ominaisuuksien ympärillä keskustelu on vasta käynnistynyt, ja niiden kehittäminen vaatii vielä runsaasti selkeytystä ja kokeiluja sekä yhteiskehittelyn tuloksena syntyviä uusia standardeja.

Rajapintojen olemassaolo ja ominaisuudet eivät kuitenkaan yksin riitä My Datan -periaatteiden toteutumiseen. Lisäksi tarvitaan henkilötiedon välittämisen ja helpon hallinnan mahdollistava palveluinfrastruktuuri, jota käsitellään tarkemmin seuraavassa luvussa.

## 2.1 Miten henkilötietoa syntyy?

Henkilötieto voi olla monen tyyppistä. Käytännössä henkilötietoa syntyy esimerkiksi digitaalisissa palveluissa kaikesta vuorovaikutuksesta asiakkaan ja palvelun välillä. Teoriassa tietoa voidaan kerätä loputtomasti, mutta olennaisempaa on tunnistaa, mikä on tarkoituksenmukaista tietoa, minkälaisen tiedon keräämiseen on lupa ja mitä tietoa kannattaa tallentaa ja jalostaa. Yrityksen palveluprosessissa tarvittava, yritykselle hyödyllinen tieto voi olla asiakkaallekin hyödyllistä jo tiedonkeruun läpinäkyvyydenkin vuoksi. Palveluprosesseissa saattaa syntyä myös sellaista tietoa, joka olisi hyödyllistä yksilölle, mutta ei palvelua tarjoavalla organisaatiolle. Tällöin organisaatiota ei voida velvoittaa keräämään kyseistä tietoa. My Datan toteutumisen myötä asiakkaat saattavat kuitenkin kokea heille hyödyllisen henkilötiedon saatavuuden ja tiedon keräämisen heidän puolestaan osaksi palvelun ominaisuuksia.

Tiedon tärkeitä määreitä ovat sen koko, ajallinen kertymistahti ja rakenne. Sijaintitieto ja syketieto ovat esimerkkejä rakenteeltaan yksinkertaisestaaikasarjadatasta; saldotieto päivittyy usein, mutta ei ole luonteeltaan jatkuvaa; osoitetieto on pääasiassa pysyvää, mutta päivittyy satunnaisesti. Datan määrällä mitattuna esimerkiksi geenitieto eroaa kengän numerosta merkittävästi. Henkilötietoa voitaisiin luokitella myös sektoreittain, kuten kuten terveystieto, liikkumistieto, oppimistieto jne., mutta My Data -lähestymisessä pyritään toimintatapoihin, jotka mahdollistavat sektorirajat ylittävän tiedon hyödyntämisen. Käytännössä tämä tarkoittaa, että henkilötieto liikkuu rajapintojen välillä ja on teknisesti yhteentoimivaa datan määrästä, päivitystahdista ja rakenteesta riippumatta. Tiedon rakenteen pitää olla riittävän kattavasti ja selkeästi kuvattu, jotta esimerkiksi eri lähteistä saatavat aikasarjatiedot voidaan yhdistää toisiinsa.

![image alt text][image-2-1]

*Kuva 2.1: Aloja, joissa syntyy paljon henkilötietoa, ovat muiden muassa liikenne, pankki- ja vakuutustoiminta, viestintä ja kommunikaatio (mukaan lukien sosiaalinen media ja muut verkkopalvelut) ja media, kuluttajakauppa ja erityisesti ruokakauppa, terveys- ja hyvinvointiala, energia ja koulutus ja oppiminen. My Data -periaatteiden toteuttaminen mahdollistaa näiden alojen sisäisen henkilötiedon hallinnan organisointia, mutta erityisesti alojen välistä tiedonsiirtoa.*

My Data -lähestyminen tuottaa lisäarvoa yhdistämällä eri lähteistä tulevaa henkilötietoa. Kuvassa 2.1 on kuvattu keskeisimmät henkilötiedon osa-alueet. Eri sektoreiden tietoja yhdistämällä palveluita tarjoava organisaatio voi nykyistä kokonaisvaltaisemmin ymmärtää yksilön tarpeita ja toimintaa. Jos palvelua kehitetään vain yhden sektorin sisällä, kerätty tieto antaa vain osittaisen kuvan ihmisen tarpeista ja toiminnasta. Esimerkiksi terveys- ja hyvinvointipalveluissa kliinisen terveystiedon lisäksi kannattaa kurkottaa muiden sektoreiden alueille: talous, liikkuminen ja median käyttö vaikuttavat myös ihmisen terveyteen. Kaikkea kulutus- ja käyttäytymistietoa voidaan hyödyntää ihmisen elämäntapojen mallintamisessa ja nykyistä parempien suositusten ja syvemmän ymmärryksen luonnissa.

## 2.2 Miten henkilötieto muuttuu My Dataksi?

Johdannossa esitettiin My Datan datalähtöinen määritelmä – My Dataa on se osa henkilötiedoista, mikä on henkilön itsensä saatavilla ja hallittavissa. Yksittäisen datalähteen, kuten vaikkapa pankkipalvelun osalta tämä toteutuu silloin, kun palveluun on olemassa rajapinta, joka täyttää tietyt tiedon saatavuuteen liittyvät ehdot.

Monilla digitaalisessa liiketoiminnassa menestyvillä yrityksillä ja verkkopalveluilla, kuten Facebookilla, Googlella, Amazonilla ja Twitterillä, on jo ohjelmointirajapinta eli API, jonka kautta voi päästä kiinni palveluissa olevaan henkilötietoon. Nämä rajapinnat ovat usein hyvin kuvattuja, ja käyttävät pääasiassa yleisesti tunnettuja avoimia rajapintastandardeja. Nykyisten rajapintojen kautta saatava tietosisältö ei kuitenkaan ole aina kovin kattavaa, koska rajapinnat suunnitellaan ensisijaisesti yritysten ja palvelujen väliseen integraatioon eikä asiakkaiden pääsyyn heitä koskevaan dataan.

Reuben Binns on määritellyt henkilötiedon saavutettavuudelle seuraavanlaiset ehdot, joita hän kutsuu henkilötiedon saatavuuden viiden tähden luokitukseksi (Binns 2013):

* **1. Henkilötieto on yksilöille saatavilla maksutta ja digitaalisessa muodossa -** esimerkiksi rajapinnan tai sähköpostin kautta ilmaiseksi ja ilman sitoutumista markkinointiviestien tai vastaavien vastaanottamiseen

* **2. Henkilötieto on koneluettavaa -** esimerkiksi CSV-muodossa

* **3. Henkilötieto on avoimessa dataformaatissa -** kuten CSV, XML tai JSON mieluummin kuin Excel

* **4. Henkilötieto on saatavilla kattavasti -** kaikki henkilötieto on saatavilla samassa paikassa ja kattavasti.  

* **5. Henkilötieto on saatavilla ajantasaisesti -** joko ajantasaisen ja säännöllisesti päivittyvän rajanpinnan kautta tai sitten reaaliaikaisesti jatkuvana syötteenä

Tiedon saatavuus voidaan määritellä selkeästi ymmärrettäväksi ehtolistaksi. Yllä olevaa listausta ei vielä tunneta kovin laajasti, mutta on oletettavissa, että ennen pitkää vastaavanlainen listaus vakiintuu käyttöön, näin on esimerkiksi käynyt avoimen datan alueella. Jo nyt organisaatio voi luoda henkilötietorajapinnan, joka toteuttaa nämä ehdot, eli My Datan datalähtöisen määritelmän.

<table>
  <tr>
    <td><b>My Datan minimitoteutus</b>
    
Monet yritykset tarjoavat jo yksilölle mahdollisuutta ladata kulutustietonsa verkkosivuilta yleensä joko Excel- tai CSV-muodossa. Esimerkiksi joidenkin suomalaisten energiayhtiöiden ja pankkien verkkopalveluista tiedon lataaminen on jo mahdollista. Lisäksi energiayhtiöiden verkkosivustoilla tarjolla olevilla sovelluksilla voi tehdä erilaisia vertailuja omaan aikaisempaan ja viiteryhmien kulutukseen.
Yhdysvalloissa on kehitetty "green button"- ja “blue button” -konseptit edistämään kuluttajien mahdollisuutta saada energiankulutus- ja terveysdataansa itselleen. Blue button on verkkosivulle sijoitettu symboli, joka osoittaa terveyspalvelun asiakkaille, että he voivat verkon kautta katsella ja ladata itselleen omat terveystietonsa.  Alun perin ratkaisu kehitettiin, jotta sotaveteraanit pystyisivät käyttämään erikoislääkäripalveluja eksoottistenkin vammojen hoidossa, ja siirtyä joustavasti erikoistuneelta yksityislääkäriltä toiselle. Green button on vastaava energian kulutustiedon latausnappi.

Tällaista manuaalista latausmahdollisuutta voidaan pitää My Datan minimitoteutuksena, joka on huomattavasti parempi kuin oman datan saaminen pyydettäessä vain paperitulosteena. Nämä ovat kuitenkin vain välivaiheen parannuksia, joissa data pitää edelleen käydä manuaalisesti lataamassa, eikä sitä voi siirtää automatisoidusti rajapintojen kautta sovelluksesta toiseen.

![image alt text][image-2-info]http://energy.gov/data/green-button ja http://www.healthit.gov/bluebutton</td>
  </tr>
</table>


## 2.3 Hallittava ja standardoitu sopiminen

Kun ihminen ottaa käyttöön uuden palvelun, häntä pyydetään hyväksymään palvelun käyttöehdot. Verkkopalvelun hyväksymisnappia painettaessa syntyy palvelusopimus. Jo nykyisin ihmisillä on arkisesti käytössään kymmenittäin erilaisia verkkopalveluja, joiden kaikkien kanssa on tehty palvelusopimus. Esineiden verkon (Internet of Things) edetessä palvelusopimusten ja niihin sisältyvien henkilötiedon käyttölupien määrä kasvaa entisestään. Kun ottaa käyttöön uutta televisiota, saattaa joutua hyväksymään ehdot, joissa lupaa, että oman viihdekulutuksen dataa saa välittää eteenpäin, ja autonavigaattorin käyttäjä saattaa joutua hyväksymään ehdot, joissa oman sijainnin tiedot välittyvät navigaattoriohjelmiston valmistajalle.

Nykyisin eri palveluiden sopimuskäytännöt vaihtelevat huomattavasti, eikä ihmisillä ole käytännöllistä mahdollisuutta hallita esimerkiksi sitä, mitä kaikkia henkilötietoihin liittyviä oikeuksia on palvelusopimusten muodossa antanut eri yrityksille. Sopimisen yhdenmukaistaminen ja hallittavuus lisäisi henkilökohtaisten digitaalisten palvelujen kokonaisuuden ymmärrettävyyttä ja käytettävyyttä ihmisille.

Hallittava ja standardoitu sopiminen edellyttää että palvelujen käyttöehdot ja henkilödatan käyttöselosteet ovat koneluettavia ja toisaalta, että yksityisyysasetuksia on mahdollista muuttaa rajapintojen kautta.

### 2.3.1 Koneluettavat käyttöehdot ja käyttöseloste

Tutustuminen kaikkien palvelujen käyttöehtoihin ja niiden ymmärtäminen on käytännössä mahdotonta, eikä yksilöllä nykyisin ole muuta neuvotteluvaraa kuin hyväksyä käyttöehdot tai olla käyttämättä palvelua. Käyttöehtojen monimutkaisuudesta on kampanjoitu ja muun muassa ongelmaa esittelevä elokuva *Terms and conditions may apply* on saanut laajaa kansainvälistä huomiota (Hoback 2013). Kehitteillä on myös standardeja ja teknisiä apuvälineitä, kuten Opennotice.org, joka pyrkii ratkaisemaan käyttöehtoihin ja palvelusopimuksiin liittyviä ongelmia rakentamalla yleisesti tunnistetun ja avoimen standardijärjestelmän käyttöehdoille.

<table>
  <tr>
    <td>![.][image-2-2a]</td>
    <td>![.][image-2-2b]</td>
  </tr>
</table>

*Kuva 2.2: Terms of Service; Didn't Read<sup>[4]</sup> -projektissa on arvioitu ja luokiteltu yleisesti käytettyjen verkkopalveluiden käyttöehtoja ja tehty niistä käyttäjille helpommin ymmärrettäviä koosteita. TOSback<sup>[5]</sup> -projekti puolestaan tarkistaa automaattisesti palveluiden alati muuttuvia käyttöehtoja ja tallentaa niiden muutoshistorian.*

[4]: https://tosdr.org/
[5]: https://tosback.org/

Verkkopalvelujen käyttöehdot jättävät palvelun käyttäjän usein heikkoon asemaan.  Esimerkiksi käyttäjien tuottaman sisällön oikeudet saattavat siirtyä palvelun tarjoajalle, ja usein palveluntarjoaja saa yksipuolisesti muuttaa käyttöehtoja. Käyttöehtojen tai kerätyn tiedon käyttötarkoituksen muutokset saattavat liittyä yrityskauppoihin tai laajojen aineistojen myyntiin. Esimerkiksi Moves -älypuhelinsovellus, joka seuraa jatkuvasti käyttäjän liikkeitä, muutti käyttöehtojaan kaksi viikkoa sen jälkeen, kun sovelluksen kehittänyt suomalaisyhtiö myytiin Facebookille. Aiemmin sovellus ei välittänyt käyttäjätietoja eteenpäin, mutta sen jälkeen tiedot menivät Facebookille (Wall Street Journal 2014).

Henkilötiedon rahallisesta arvosta voi saada osviittaa laajojen henkilötietoaineistojen myyntiuutisista.  Esimerkiksi  amerikkalainen lentoyhtiö Delta sai Skymiles-bonusohjelmansa datasta luottokorttiyhtiö American Expressiltä yli puoli miljardia euroa (Taloussanomat 2014). Yksilö harvoin ymmärtää henkilötietojensa arvoa yrityksille. Äärimmäisenä esimerkkinä ovatkin ne yritykset, joiden arvo määräytyy pääosin asiakkuuksista kerätystä tiedosta. Tällaisten yritysten toiminta tai liiketoimintamallit eivät yleensä näy henkilöille, joista kerättyjä tietoja ne myyvät. Yksityisyydensuojaa digitaalisessa taloudessa käsittelevässä toimintaohjeessa Presidentti Obaman hallinto suosittelee, että asiakkaiden tietoja käsittelevien kolmansien osapuolien (data brokers), jotka eivät ole suorassa kontaktissa asiakkaiden kanssa, tulisi tarjota sitä paremmat työkalut asiakkaille saada tietoa tiedonkäsittelystä, mitä sensitiivisemmästä tiedosta on kyse (White House 2012).

![image alt text][image-2-3]

*Kuva 2.3: Kaavio Creative Common lisenssin toiminnasta esimerkkinä kuinka lisensseistä voidaan tehdä ihmisille ymmärrettäviä ja standardoituja<sup>[6]</sup>*

[6]: http://creativecommons.fi/lisenssit/valitse-lisenssi/

My Data -mallissa ei ole tarkoitus estää yrityksiä ansaitsemasta henkilötiedolla. Olennaista on tehdä ansaintamallit läpinäkyviksi ja avata yhteiskunnallista keskustelua siitä, millainen henkilötiedon hyödyntäminen on kestävää. Esimerkiksi kohdennettu mainonta, jonka kohdistamisen toimintaperiaatteista tai edes olemassaolosta yksilö ei ole tietoinen on eettisesti arveluttavaa. Usein ihmiset hyötyvät kohdentamisesta, mutta haluaisivat ymmärtää kohdentamisen perusteet. Ihmiset voisivat myös parantaa kohdentamista tuottamalla tai tarjoamalla enemmän tietoa itsestään, mutta tämä vaatii läpinäkyvyyttä ja sen pitää olla vapaaehtoista. My Data -periaatteissa pyritään tällaiseen progressiiviseen suhtautumiseen henkilötiedon hyödyntämisessä.  

Jotta käyttäjien olisi helppo ymmärtää käyttöehtoja, niiden pitäisi olla mahdollisimman selkeitä ja rakenteeltaan yhtenäisiä. Nykyisin palvelujen käyttöehdot poikkeavat toisistaan rakenteellisesti, joten niitä on mahdotonta esittää yksinkertaisina valintoina tai visualisointeina. Jatkossa voisimme kehittää yhtenäisiä standardeja rakenteisessa muodossa julkaistaville käyttöehdoille. Niissä pitäisi pyrkiä vastaavanlaiseen yksinkertaisuuteen, johon Creative Commons -lisensseissä on päästy. Valitessaan oikeaa lisenssiä tekijänoikeuksien haltijan tarvitsee vastata vain muutamaan kysymykseen, kuten saavatko muut muokata sisältöä tai käyttää ja levittää sitä kaupallisesti (kuva 2.3).Käyttöehdoissa voitaisiin kysyä, saako dataa myydä tai luovuttaa eteenpäin, saako dataa luovuttaa viranomaisille, miten kauan dataa säilytetään jne. Vakiomuotoiset käyttöehdot voitaisiin visualisoida vaihtoehtoja kuvaavilla ikoneilla. Esimerkiksi aiemmin Mozilla-säätiölle työskennellyt Aza Razkin on konseptoinut verkkosivuille tarkoitettua ikonisarjaa (kuva 2.4), jolla voi kuvata, miten verkkosivu käyttää tallentamiaan henkilötietoja.

<table>
  <tr>
    <td>![.][image-2-4a]</td>
    <td>![.][image-2-4b]</td>
    <td>![.][image-2-4c]</td>
  </tr>
</table>
*Kuva 2.4: Aza Razkinin tekemä ikonisarja Mozilla-säätiölle kuvaamaan kuinka verkkosivut tallentaa henkilötietoa*

Käyttöehdot ovat staattinen dokumentaatio, jota luodessaan organisaatio on pyrkinyt varautumaan erilaisiin henkilötiedon tulevaisuuden hyödyntämismahdollisuuksiin. Tästä syystä niissä ei määritellä kovinkaan rajaavasti, mihin tietoa voidaan käyttää. Palvelusuhteen aikana tapahtuu yleensä paljonkin muutoksia sen suhteen minne tietoa siirretään. Laki rajoittaa tiedon jatkohyödyntämistä alkuperäisestä poikkeaviin tarkoituksiin. Siitä huolimatta yritysten välillä tehdään jatkuvasti kauppaa henkilötiedoilla, yllä esitetty Delta Airlinesin esimerkkitapaus on vain yksi monista vastaavista. Jotta yksilö pysyisi perillä siitä, mitä tiedolla missäkin vaiheessa tehdään, olisi läpinäkyvyyden nimissä tärkeää luoda käytänteitä, joilla yritys voisi ilmoittaa henkilötiedon käytöstä. Tällainen käyttöseloste voisi yksinkertaisemmillaan olla ilmoitus, jossa kerrotaan, että nyt organisaatio on aloittanut tiedon välittämisen toiselle organisaatiolle saatuaan aiemmin asiakkaan suostumuksen tiedon välittämiseen.

### 2.3.2 Yksityisyysasetusten hallinta rajapintojen kautta

Yksityisyysasetusten hallinta rajapintojen kautta tarkoittaa, että käyttäjällä voi olla yksi paikka, josta hän voi kerralla määritellä yksityisyyteen ja datan käyttöön liittyvät asetukset useammassa käyttämässään palvelussa. Vastaavalla tavalla kuin rajapinnat mahdollistavat nykyisin sen, että esimerkiksi Foursquare-sovelluksesta voi lähettää viestin Twitteriin ja Facebookiin, niin tulevaisuudessa yksilö voisi My data -tilinsä hallintasovelluksesta säätää yksityisyysasetukset kaikkiin niihin palveluihin, jotka tukevat yksityisyysasetusten hallintaa rajapinnassaan.Nykyiset palvelut eivät vielä mahdollista yksityisyysasetusten hallintaa rajapintojen kautta, vaan asetuksia säädetään palvelun sisällä. Sujuva palvelujen etähallinta edellyttää myös yleisiä käytäntöjä siitä, millaisia yksityisyysasetuksia ja -valintoja eri palveluissa on.

Alla on lueteltu yksityisyysominaisuuksia, joiden asetuksia etähallinnalla voisi säätää:

* Mitä tietoa palvelu saa käyttötilanteessa haltuunsa (esimerkiksi mobiililaitteesta sijainti tai kontaktitietoja)?

* Mitä tietoa palvelun sisällä voidaan näyttää muille käyttäjille?

* Mitä tietoa palvelun tarjoaja voi hyödyntää suoraan liiketoiminnassa kumppaneidensa kanssa (esimerkiksi kohdennettu markkinointi)?

* Mitä tietoa palvelu voi tallentaa käyttäjästä (osa tiedosta, kuten sijainti, voi olla sellaista, jota käyttäjä voi haluta antaa palvelun hyödyntää reaaliaikaisesti, mutta ei tallentaa)?

* Mitä tietoa palvelu lähettää suoraan eteenpäin rajapinnan kautta (reititys toiseen palveluun ilman operaattoria)?

* Mitä tietoa palvelu lähettää käyttäjän omaan tietovarastoon (käyttäjällä voi olla esimerkiksi My data -operaattorin ylläpitämä oma tietovarasto, josta käyttäjä voi edelleen ohjata tietojaan muille tahoille)?

![image alt text][image-2-5]

*Kuva 2.5: Esimerkki yhdenmukaisista yksityisyysasetuksista on Android-sovellusten "application permissions", mitä jokaisen Android-sovelluksen on kysyttävä käyttäjältä ennen asennusta.*

Kuvassa 2.5 esitetty Android-sovellusten yksityisyysasetusten lista on konkreettinen esimerkki siitä, miten henkilötiedon keräämistä voidaan sovelluskohtaisesti luokitella ja muodostaa yhteisesti sovittu malli, jonka mukaan kaikki palveluntarjoajat määrittelevät omaa tiedonkeruutaan. Android-sovellusten yhdenmukainen lista yksityisyysasetuksista on askel oikeaan suuntaan, mutta ihmisillä ei kuitenkaan ole mahdollisuutta vaikuttaa siihen, mitä oikeuksia millekin sovellukselle antaa, ainoa vaihtoehto on olla asentamatta sovellusta, mikäli ei halua antaa kaikkia sovelluksen pyytämiä lupia. Suurin osa ihmisistä ei tarkastele sovellusten käyttöoikeuksia kovinkaan kriittisesti ennen asentamista.

Yhtenäinen malli yksityisyysasetuksiin ja mahdollisuus hallita asetuksia rajapintojen kautta yhdessä mahdollistavat My Data -hallintapalvelujen tekemisen. Tällaisen palvelun avulla yksilö voi saavuttaa keskitetyn hallinnan ja kattavan kuvauksen oman henkilötietonsa virtaamisesta digitaalisessa maailmassa.

Kun rajapinnat toteuttavat My Datan ehdot, organisaatiot tuottavat kattavan käyttöselosteen ja yksityisyysasetuksia voidaan etähallita, olemme lähellä ohjelmallista sopimista; organisaation ja yksilön välillä vallitsee aktiivinen sopimusprosessi, joka ylläpitää tilaa sopimukseen liittyvän tiedon hyödyntämisestä ja mahdollistaa sopimusehtojen muuttamisen hallitusti ja molemminpuoleisesti.

## 2.4 Rajapintoihin liittyvät standardit ja formaatit

Yleisesti käytössä olevat standardit ovat edellytys helposti toteutettavalle palvelujen väliselle yhteentoimivuudelle. Avoimet standardit ovat puolestaan edellytys avoimille markkinoille. Avoimilla standardeilla tarkoitetaan sellaisia, joiden käyttöön kaikilla on yhtäläiset mahdollisuudet, joiden käytöstä ei peritä maksua ja joiden kehitystyö on avointa eikä minkään yksittäisen yrityksen hallitsemaa.

Henkilötiedon alueella nykytilanne on se, että suurelta osin toimijoiden tietomallit on suunniteltu omien tarpeiden ympärille. Niiden yhteneväisyys esimerkiksi kilpailijoiden tai muiden sektorien toimijoiden kanssa on heikkoa. Kun tiedon yhdistäminen useasta lähteestä yleistyy, kasvaa myös tarve yhtenäisille tietomalleille. Organisaatiot siirtyvät käyttämään yhdessä sovittuja standardeja itse kehittämiensä sijaan. Tämä voi hyödyttää organisaatiota tulevien tietojärjestelmien määrittelyssä ja toteutuksessa.

My Datan kehityksessä tarvitaan avoimia standardeja eri alueilla. Usein puhutaan standardoinnin eri tasoisista, niin että ylemmän tason standardit tukeutuvat alempiin tasoihin. Käytännössä esimerkiksi internetin sovelluksiin ja dataan liittyvät standardit muodostavat toisiaan täydentävän verkoston, eikä niitä voida asettaa selkeään hierarkiaan, vaikka niin sanotussa OSI-mallissa<sup>[7]</sup> (Open Systems Interconnection model) tätä yritettiinkin.

[7]: http://en.wikipedia.org/wiki/OSI_model

Myös My Data -standardikehitystä on syytä lähestyä käytännöllisesti ilman kerrosrakennetta. Standardit kyllä tukeutuvat toisiinsa ja rakentavat kokonaisuutta yhdessä, mutta eivät hierarkkisessa järjestyksessä. Ei siis ole välttämättä mitään "pohjimmaisia" My Data -standardeja vaan eri standardeilla on erilaisia funktioita, joita yhdistelemällä saavutetaan systeemin tasolla hyvä yhteentoimivuus. Alla on listattu muutamia My Dataan liittyviä standardeja.

* Rajapintastandardit (REST)

* Dataformaatit, henkilötiedon tietomallit ja semantiikat (XDI, RDF ja W3C Linked data)

* Tiedon salaus ja kryptausmenetelmät (Bitcoin)

* Todentamiseen ja valtuuttamiseen liittyvät standardit (OAuth)

* Profiilitietoon liittyvät standardit (Orcid)

* Tiedon välittämiseen ja delegointiin liittyvä hallinnointistandardi (Respect Network)

* Tiedon lisensointiin ja käyttöehtoihin liittyvät standardit (Creative Commons, Open Notice)

Näiden standardien kehitystyö on jatkuvaa ja useimmiten avointa. Alkuvaiheessa on hyvä ymmärtää standardien kehityksen tila ja tehdä olemassa olevia standardeja hyödyntäviä kokeiluja, joiden avulla selviävät eri standardien mahdollisuudet ja yhteensopivuus. Uusien standardien kehityksessä on pyrittävä laajennettavuuteen, jotta vältytään tilanteelta, jossa lukittu, vanhanaikainen ja jäykkä standardi estää innovaation.  

Standardien välillä vallitsee jatkuva kilpailu. Esimerkiksi yritykset pyrkivät edistämään omia tai itselleen edullisia standardeja. My Datan suunnittelussa on keskeistä, että toiminnan ytimessä olevat standardit ovat selkeitä ja yksinkertaisia, ja järjestelmä muuten kykenee hyödyntämään useita erilaisia kilpailevia standardeja.

<table>
  <tr>
    <td><b>Datakuitti - yksinkertainen tapa toteuttaa rajapinta</b>

Datakuitti voisi olla joillekin yrityksille mahdollisimman helppo ensiaskel kohti My Data rajapinnan kehittämistä. Kun käyn kaupassa, saan kuitin lompakkooni. Vastaavalla tavalla voisin saada datakuitin datalompakkooni automaattisesti jokaisesta ostostapahtumasta tai koosteena vaikkapa kerran kuukaudessa. Datakuitti sisältäisi kattavasti tiedot, jotka yritys on kerännyt minusta asiakkaana ostotapahtuman yhteydessä. Datakuittiin voitaisiin liittää muutakin saatavilla olevaa tietoa kuten ostossisältöön liittyviä tuotekoodeja, ravintoselosteita, takuutietoja jne.
Yrityksen taustajärjestelmiin pitäisi avata mahdollisuus datakuitin automaattiseen lähettämiseen. Lisäksi yrityksen tulisi kuvata prosessit, joilla asiakas ottaa datakuitin käyttöönsä. Kevyimmillään datakuitin välittäminen voidaan toteuttaa vaikkapa sähköpostilla, jolloin datalompakkona toimisi tavallinen sähköpostitili. Käytännössä asiakas saa kuitin sähköpostiinsa, kun kirjoittaa kassapäätteeseen sähköpostiosoitteensa. Apple alkoi tarjoata tällaisia sähköpostitse lähetettäviä datakuitteja jo vuonna 2005. Sen jälkeen monet muutkin kauppaketjut ja palveluntarjoajat, kuten Urban Outfitters, Nordstrom, Macy’s, Dick’s Sporting Goods, Dillard’s and Avis ovat seuranneet perässä (Charski 2013). Edistyneet syöteformaatit avaavat lisää mahdollisuuksia, mutta edellyttävät käyttäjiltä erikoistuneita työkaluja ja palveluita datakuittien vastaanottamiseen.

Ero paperikuitteja pursuavan nahkalompakon ja datalompakon välillä on se, että jälkimmäiseen voidaan asentaa hyödyllisiä ohjelmia, jotka käsittelevät ja havainnollistavat tietoa. Datalompakossa voi toimia vaikkapa reaaliaikainen talousseurantaohjelma. Luonnollisesti käyttäjä voi itse valita, mitä ohjelmia datalompakkoonsa asentaa, mutta kauppias voi myös suositella ohjelmia, jotka erityisesti ottavat huomioon hänen lähettämänsä datan. Datakuitin voi toteuttaa monella tapaa, ja datakuittia toteutettaessa on tärkeää, että data on hyvin määriteltyä, koneen luettavassa ja avoimessa muodossa eikä esimerkiksi pelkästään kuvaksi printtatuna pdf-tiedostona. </td>
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
[image-2-2a]: images/image-2-2a.png
[image-2-2b]: images/image-2-2b.png
[image-2-3]: images/image-2-3.png
[image-2-4a]: images/image-2-4a.jpg
[image-2-4b]: images/image-2-4b.jpg
[image-2-4c]: images/image-2-4c.jpg
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