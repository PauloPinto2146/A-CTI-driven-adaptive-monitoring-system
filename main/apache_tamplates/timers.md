## Cenários e os timers

Para tornar os cenários o mais realista possível é preciso ter em conta que um utilizador normalmente demora a fazer ações. Pensa, digita em campos e explora. Ações que demoram tempo e precisam ser considerdas.

Retirando os tempos definidos em: https://www.testerrank.com/paths/performance/key-metrics/think-time-and-pacing
Cada cenário terá um timer (Random uniform timer no apache jmeter) para implementar um teste com maior realismo.

De seguida apresento os cenários em conjunto com os seus tempos mínimos, máximos e médios, assim como a especificação de cada ação e o tempo que demora:

- Procurar item: 5-50s
	- Typing the item (1-10s) - apple
	- Typing the item (1-10s) - orange
	- Typing the item (1-10s) - lemon
	- Typing the item (1-10s) - melon
	- Typing the item (1-10s) - juice
Tempo médio: 27.5s

- Shopping: 14-180s
	- Putting money in the account: Filling short form timer (3-30s)
	- Getting item info: Reading product description (5-60s)
	- Cleaning item cart: Browsing timer (2-30s)
	- Going to the delivery page and selecting the options: Browsing timer (2-30s)
	- Checking out: Browsing timer (2-30s)
Tempo médio: 97s

- Reading items' descriptions: 40s-450s
	- Browsing a list/catalog (3-30s) + Reading product description (5-60s)
	- Browsing a list/catalog (3-30s) + Reading product description (5-60s)
	- Browsing a list/catalog (3-30s) + Reading product description (5-60s)
	- Browsing a list/catalog (3-30s) + Reading product description (5-60s)
	- Browsing a list/catalog (3-30s) + Reading product description (5-60s)
Tempo médio: 245s

- Post memory: 18-210s
	- Scrolling through memories: Browsing timer (3-30s)
	- Selecting the memory to publish: Filling long form timer (15-180s)
Tempo médio: 114s

- Register: 5-60s
	- Browing timer (2-30s)
	- Filling short form timer (3-30s)
Tempo médio: 32,5s

- Login: 5-60s
	- Browing timer (2-30s)
	- Filling short form timer (3-30s)
Tempo médio: 32,5s


## Proporções

Para além de ter em conta os tempos de pensar (think time) temos que ter em conta que em aplicações de comércio nem todos os pedidos são distribuídos de igual forma. Por exemplo, um pedido para fazer log in, em princípio, é muito menos requisitado do que a informação de um produto qualquer.
O TPC-W especifica uma workload de e-commerce que simula as atividades de uma aplicação de vendas.
Nesse paper tem especificado as proporções de pedidos para WIPS ("Web Interaction Mix for Shopping"):

| Interação web         | Browsing (WIPSb) | **Shopping (WIPS)** | Ordering (WIPSo) |
| --------------------- | ---------------- | ------------------- | ---------------- |
| Browse                | 95,00 %          | **80,00 %**\*       | 50,00 %          |
| Home                  | 29,00 %          | **16,00 %**         | 9,12 %           |
| New Products          | 11,00 %          | **5,00 %**          | 0,46 %           |
| Best Sellers          | 11,00 %          | **5,00 %**          | 0,46 %           |
| Product Detail        | 21,00 %          | **17,00 %**         | 12,35 %          |
| Search Request        | 12,00 %          | **20,00 %**         | 14,53 %          |
| Search Results        | 11,00 %          | **17,00 %**         | 13,08 %          |
| Order 		        | 5,00 %           | **20,00 %**\*       | 50,00 %          |
| Shopping Cart         | 2,00 %           | **11,60 %**         | 13,53 %          |
| Customer Registration | 0,82 %           | **3,00 %**          | 12,86 %          |
| Buy Request           | 0,75 %           | **2,60 %**          | 12,73 %          |
| Buy Confirm           | 0,69 %           | **1,20 %**          | 10,18 %          |
| Order Inquiry         | 0,30 %           | **0,75 %**          | 0,25 %           |
| Order Display         | 0,25 %           | **0,66 %**          | 0,22 %           |
| Admin Request         | 0,10 %           | **0,10 %**          | 0,12 %           |
| Admin Confirm         | 0,09 %           | **0,09 %**          | 0,11 %           |

- TPC-W paper (Márk Kaszó, Tihamér Levendovszky, 2006) https://conf.uni-obuda.hu/huci2006/43_Kaszo.pdf

Ou seja:

| Sequência         | Peso  | Derivação                                                                                                         |
| ----------------- | ----- | ----------------------------------------------------------------------------------------------------------------- |
| Procurar item     | 37 %  | Search request 20% + Search result 17% |
| Ler descrições    | 33 %  | Home 16% + Product Detail 17% |
| Shopping          | 16,81 %  | Shopping Cart 11,6% + Buy Request 2,6% + Buy Confirm 1,25 + Order Inquiry 0,75% + Order display 0,66%                  |
| Registar*          | 2,1 %   | Customer Registration 3% x 0,7 (proporção de registo e login)                                                                     |
| Login*          | 0,9 %   | Customer Registration 3% x 0,3 (proporção de registo e login)                                                                     |
| Publicar memória 	| 10,19%	| Extensão, dada pelo espaço libertado de New Products 5% + Best Sellers 5% + Admin request 0,1% + Admin confirm 0,09% 
| Total             | 100 % | browse:order = 80:20 — valor canónico do WIPS                                                                     |

\* This secure web interaction returns to the EB a web page which allows a User to provide the information necessary to register as a known Customer or as a new Customer and to submit their registration. This is the first step in buying the contents of the CART. (https://www.tpc.org/miscellaneous/TPC_W.folder/tpcw-d51a.pdf)

Como o TPC-W não diferencia registo de login, preciso de justificação externa.
Com o valor de referência de ~30 % de visitantes recorrentes (https://www.opensend.com/post/new-vs-returning-visitors-statistics-ecommerce - "A healthy returning visitor rate benchmarks around 30%")


Com as proporções e com os cenários **Leve** (25 threads), **Médio** (100 threads) e Alto (400 threads) 

| Thread Group      | Peso   | Leve | Médio | Alto | Tempo médio (s) |
| ----------------- | -----  | ---- | ----- | ---- | --------------- |
| Procurar item     | 37,0 % | ~9   | 37    | 148  | 27,5            |
| Ler descrições    | 33,0 % | -8   | 33    | 132  | 245             |
| Shopping  		| 16,81 %| ~4   | ~17   | ~67  | 97              |
| Registo 		    | 2,1 %  | ~1   | ~2    | ~8   | 32,5            |
| Login             | 0,9 %  | 0    | ~1    | ~4   | 32,5            |
| Publicar memória  | 10,19 %| ~3   | ~10   | ~41  | 114             |
| Total             |        | 25   | 100   | 400  | 				 |

Mas se assim fosse, com loops infinitos, por exemplo, o login, que tem menor tempo de processamento, iria correr muitas mais vezes do que esperado e não iria respepitar o 0,9% de requisitos que realmente queremos.
Ou seja, tenho que arranjar uma maneira de adaptar estes números com os seus tempos médios.

A **lei de Little** (https://loadtest.help/knowledge/littles-law.html) diz-nos que:

$$ N = \Lambda * T $$

onde:
- N = Nº de items concorrents no sistema (threads)
- lambda = Throughput (percentagens)
- T = Tempo que cada item passa no sistema (tempo médio)

Ora, querendo eu descobrir quantas threads terei eu de correr por cada *thread group* e sabendo lambda e T de cada um:

$$ N_{Ler descrições} = 33 * 245 = 8085$$ 
$$ N_{Procurar item} = 37 * 27,5 = 1017,5$$ 
$$ N_{Shopping} = 16,81 * 97 = 1630,6$$ 
$$ N_{Publicar memória} = 10,19 * 114 = 1161,7$$ 
$$ N_{Registo} = 2,1 * 32,5 = 68,25 $$ 
$$ N_{Login} = 0,9 * 32,5 = 29,25$$ 

Com estes novos valores podemos achar os pesos reais que pretendemos usar para que, contando com o tempo médio, possamos definir o número de threads a usar num total de 400.
Medindo agora os novos pesos, precisamos de saber o total de threads anteriormente calculadas:

$$ N_{Ler descrições} + N_{Procurar item} + N_{Shopping} + N_{Publicar memória} + N_{Registo} + N_{Login} = $$
$$ 8085 + 1017,5 + 1630,6 + 1161,7 + 68,25 + 29,25 = $$
$$ 11992,3 $$

Para calcular as proporções (P) corretas precisamos apenas de dividir os N's pelo total:

$$ P_{Ler descrições} = N_{Ler descrições} / Total = 8085 / 11992,3 = 0,6742 $$
$$ P_{Procurar item} = N_{Procurar item} / Total = 1017,5 / 11992,3 = 0,0848 $$
$$ P_{Shopping} = N_{Shopping} / Total = 1630,6 / 11992,3 =  0,1360 $$
$$ P_{Publicar memória} = N_{Publicar memória} / Total = 1161,7 / 11992,3 = 0,0970 $$
$$ P_{Registo} = N_{Registo} / Total = 68,25 / 11992,3 = 0,0057 $$
$$ P_{Login} = N_{Login} / Total = 29,25 / 11992,3 = 0,0024 $$

Ou seja:

| Thread Group      | **P**    | Leve | Médio | Alto |
| ----------------- | -------- | ---- | ----- | ---- |
| Procurar item     | 8,48 %   | ~2   | ~8    | ~34  |
| Ler descrições    | 67,42 %  | ~17  | ~67   | ~270 |
| Shopping  		| 13,6 %   | ~4   | ~14   | ~54  |
| Registo 		    | 0,57 %   | 0    | ~1    | ~2   |
| Login             | 0,24 %   | 0    | 0     | ~1   |
| Publicar memória  | 9,7 %    | ~2   | ~10   | ~39  |
| Total             |          | 25   | 100   | 400  |


### Ramp-up
O valor de ramp-up será escolhido para que cada thread tenha pelo menos 0.5s entre cada uma.
Ou seja:

| Thread Group      | Leve (N) | Médio | Alto | Ramp-up (s)  |
| ----------------- | -------- | ----- | ---- | ------------ |
| Procurar item     | ~2       | ~8    | ~34  | 1 / 4 / 17	 |
| Ler descrições    | ~17      | ~67   | ~270 |	9 / 34 / 135 |
| Shopping  		| ~4       | ~14   | ~54  | 2 / 7 / 27   |
| Registo 		    | 0        | ~1    | ~2   | 0 / 0 / 1 	 |
| Login             | 0        | 0     | ~1   | 0 / 0 / 0 	 |
| Publicar memória  | ~2       | ~10   | ~39  | 1 / 5 / 20   |
| Total             | 25       | 100   | 400  | -			 |