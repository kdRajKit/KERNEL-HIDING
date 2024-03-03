# KERNEL-HIDING
KERNEL-SHELLCODE-HIDING-BY-PTE


<span class="c13 c8 c25"></span>

<a id="t.623a35a4ebefa37676805f73533882f57167a056"></a><a id="t.0"></a>

<table class="c35">

<tbody>

<tr class="c29">

<td class="c30" colspan="1" rowspan="1">

<span class="c13 c8 c31">REVERSING DE SISTEMAS WINDOWS</span><span class="c13 c8 c27"> </span>

</td>

</tr>

<tr class="c29">

<td class="c30" colspan="1" rowspan="1">

<span class="c7"></span>

</td>

</tr>

<tr class="c29">

<td class="c30" colspan="1" rowspan="1">

<span class="c14 c21 c8 c24">RajKit</span>

</td>

</tr>

</tbody>

</table>

<span class="c7"></span>

<span class="c7"></span>

<span class="c13 c8 c36">1.- Introducción</span>

<span class="c1">Aprovecharemos la posibilidad de monitorear y proteger nuestro código en user desde RING0.</span>

<span class="c1"></span>

<span class="c1">Para ello me voy a basar en la arquitectura de paginación de windows, la traducción de direcciones virtuales y los registros de control que proporciona Intel.</span>

<span class="c1"></span>

<span class="c1">El proceso se realiza de la siguiente manera:</span>

<span class="c1"></span>

*   <span class="c1">Reservaremos 2 espacios en Ring3 y inyectamos la shellcode en uno de ellos</span>
*   <span class="c10">Usaremos</span> <span class="c4">DeviceIoControl</span><span class="c1"> para comunicarnos con el driver.</span>
*   <span class="c1">En el driver iremos escalando desde el registro CR3 y la dirección virtual hasta obtener la Page Table Entry y su marco de página.</span>
*   <span class="c1">Des-referenciamos el espacio de memoria “shellcode” asignándole otro pfn a la PTE de su dirección virtual como la de el espacio benigno.</span>

<span class="c1"></span>

<span class="c1">De esta forma mantendremos oculto ese espacio de memoria reservado dentro del proceso que queramos</span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c13 c18 c8">2.- Dirección virtuales, físicas, paginación y WinDBG</span>

<span class="c10">Todo lo que hacemos se basa en</span> <span class="c4">PAE</span><span class="c10">, que se habilita a través de uno de los bits de control del registro</span> <span class="c4">CR4</span><span class="c1"> del procesador, concretamente el sexto bit empezando de la derecha:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 618.00px; height: 102.47px;">![image11](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/46a5d58a-c820-46e0-afcf-86a562815e87))</span>

<span class="c1">Ahora pasemos a despiezar lo que conocemos como dirección virtual, que es lo que representa cada parte y como se accede desde la base de la tabla PML4 a través de la dirección de memoria física que contiene el registro CR3 a la diferentes estructuras principales de paginación para llegar a la PTE y obtener la dirección física de la pagina correspondiente:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px 0.00px; border: 0.00px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 561.47px; height: 292.33px;">![image6](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/ef54a766-ebde-48b3-ac05-40b4198f04bc)
</span>

<span class="c1">En el diagrama que e hecho se explica un poco el recorrido de la traducción, de tal forma que cada 9 bits desde el bit 47 se realiza un cálculo con el offset de la estructura de paginación y el registro de esa estructura se indexa para acceder a la siguiente estructura de paginación y terminar en la dirección física lineal correspondiente a esa dirección virtual lineal.</span>

<span class="c1"></span>

<span class="c1">De esta forma tenemos 4 estructura de paginación responsables de esta traducción:</span>

<span class="c1"></span>

*   <span class="c4">PML4</span><span class="c10">→</span> <span class="c14">bits 47-39</span><span class="c10">→</span> <span class="c12">2^9=512</span><span class="c14"> posibles indexaciones</span>
*   <span class="c4">PDPE</span><span class="c10">→</span> <span class="c14">bits 38-30</span><span class="c10">→</span> <span class="c12">2^9=512</span><span class="c14"> posibles indexaciones</span>
*   <span class="c4">PDE</span><span class="c10"> →  </span><span class="c14"> bits 29-21</span><span class="c10"> →  </span><span class="c12">2^9=512</span><span class="c14"> posibles indexaciones</span>
*   <span class="c4">PTE</span> <span class="c10">→</span> <span class="c14">bits 20-12</span><span class="c10"> →  </span><span class="c12">2^9=512</span><span class="c14"> posibles indexaciones</span>

<span class="c1"></span>

<span class="c1">Con lo que terminaríamos obteniendo la dirección física de la página correspondiente la cual en 64bits seria</span>

*   <span class="c4 c20">2^12</span><span class="c10">=</span><span class="c4">4096 bytes → 4K</span>

<span class="c13 c4 c8"></span>

<span class="c10">Siempre y cuando en los bits de control de la estructura PDPTE no tengamos activado</span> <span class="c4">page_size</span><span class="c10">, lo que permitiría crear Large Pages de 1GB y cambiar un poco la transición de la traducción, ya que se prescinde de las PTE y se accedería directamente desde PDE</span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c10">Visto muy por encima el proceso de traducción y antes de explicar la técnica que trataremos desde el driver vamos a pasar al Windbg que mediante un ejemplo obtendré los flags de control de una entrada</span> <span class="c4">PTE</span><span class="c1"> para modificarlo y ver qué ocurre, que en este caso será la shellcode que inyectamos en un espacio de direcciones reservado por nosotros, para ello tenemos este código:</span>

<span class="c1"></span>

*   <span class="c26">VirtualAlloc</span><span class="c8 c26">→</span> <span class="c6">Reservamos espacio con permisos</span> <span class="c12">0x40</span><span class="c6"> (PAGE_EXECUTE_READWRITE)</span>
*   <span class="c26 c8">MoveMemory →</span><span class="c12"></span> <span class="c6">[payload] ('\x90')</span>
*   <span class="c26 c8">VirtualProtect →</span><span class="c12"> </span><span class="c6">Cambiamos permisos a solo lectura → (</span><span class="c6">PAGE_READONLY</span><span class="c6">)</span>
*   <span class="c26 c8">MoveMemory →</span><span class="c12"> </span><span class="c6">[payload2] ('\x00')</span>

<span class="c1"></span>

<span class="c10">Por lo tanto cambiaremos los permisos mediante la modificación del bit de control</span> <span class="c4">R/W</span><span class="c10">de la PTE correspondiente a las entradas de página de la dirección virtual del espacio reservado, para permitir</span> <span class="c4">RtlMoveMemory()</span><span class="c1"> del segundo payload.</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 538.40px; height: 446.13px;"><![image4](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/5f42b73f-53f2-4bfa-b28f-273189e9c5cd)
/span>

<span class="c1">Ejecutamos el programa en el GUEST y desde WinDBG nos ponemos en el contexto del proceso para hacer un volcado de la dirección del espacio reservado:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 590.33px; height: 107.33px;">![image14](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/58d8b2fc-86aa-43ac-8a46-00064ed14ae4)
</span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c10">Tenemos nuestro espacio reservado y los NOP´s escritos en la dirección virtual</span> <span class="c4">0x18000</span><span class="c1">:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 586.40px; height: 108.07px;">![image16](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/89726241-8606-45fd-af0a-44d2420d702c)
</span>

<span class="c10">En este punto de la ejecución, nos encontramos con los permisos en</span> <span class="c4">PAGE_READONLY</span><span class="c10">después de ejecutar</span> <span class="c4">VirtualProtect()</span><span class="c1">, podemos comprobarlo mediante el comando !pte:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 581.27px; height: 71.80px;">![image20](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/9e12d7f2-6808-4889-9097-6d62c19c7007)
</span>

<span class="c1">Cada estructura de paginación nos proporciona unos flags de control, en nuestro caso solo nos interesan los de la Page Table Entry:</span>

<span class="c1"></span>

*   <span class="c4">BIT 1</span><span class="c10">→</span> <span class="c16 c34">READ/WRITE</span>
*   <span class="c4">BIT 2</span><span class="c10">→</span> <span class="c34 c16">USER/SUPERUSER</span>
*   <span class="c4 c8">BIT 61 →</span> <span class="c34 c16">NX (NO EXECUTE)</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px 0.00px; border: 0.00px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 161.47px; height: 83.67px;">![image21](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/438b2b0c-d9b1-469a-8a23-8424f8d3f4ab)
</span>

<span class="c1">Comprobamos traduciendo a binario el contenido de esta Page Table, si el segundo bit se encuentra desactivado significa que solo es de lectura:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 589.60px; height: 80.33px;">![image5](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/08207295-c5d4-434a-bcd5-e9146267ab78)
</span>

<span class="c1"></span>

<span class="c10">Activamos ese BIT y sobre-escribimos el puntero que contiene la dirección de nuestro</span> <span class="c10">PTE</span><span class="c10">en</span> <span class="c4">FFFFDA8000000C00</span><span class="c10">:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 200.00px; height: 84.87px;">![image22](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/76fdb903-d6ca-4d43-822d-bf3b858a8944)
</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: -0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 598.00px; height: 150.93px;">![image12](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/cd46474b-cafe-4e11-b36c-25cc00c123b0)
</span>

<span class="c10">Conseguiremos escribir en ese espacio de memoria? Continuamos con la ejecución del programa en RING3 y volvamos a hacer un volcado de esa dirección, deberíamos tener un slide de</span> <span class="c4">'\x00'</span><span class="c1">:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: -0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 597.67px; height: 191.13px;">![image1](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/3563b9a6-21d8-4913-9004-86ce1a4d7c96)
</span>

<span class="c13 c18 c8">3.-</span> <span class="c18">SUBVERSIÓN</span><span class="c13 c18 c8"> DE LA MEMORIA</span>

<span class="c10">Si bien existen varias técnicas que nos permiten ocultar partes seleccionadas de la memoria de un proceso en la aplicación de espacio de usuario, solo hablare de una ellas que será la que implementaremos en nuestro driver será el “</span><span class="c4">PTE</span> <span class="c4">REMAPING</span><span class="c1">”.</span>

<span class="c1"></span>

<span class="c10">Qué es lo que conseguimos con esta técnica? Antes hemos visto que una entrada PTE contiene un marco de página llamado</span> <span class="c4">pfn</span><span class="c10">, que sin entrar en detalles básicamente los PTE obtienen el</span> <span class="c4">pfn</span><span class="c10">para la siguiente estructura de paginación, por los tanto en un contexto de x64 donde las páginas físicas son de</span> <span class="c4">4096</span><span class="c10">bytes es decir</span> <span class="c4">0x1000</span><span class="c10">, y multiplicando ese</span> <span class="c4">pfn</span><span class="c1"> por el tamaño de la página física nos daría una dirección de memoria física!!</span>

<span class="c1"></span>

<span class="c10">Comprobemos que es cierto en WinDBG y dentro del contexto del programa del ejemplo anterior, tenemos una shellcode de '</span><span class="c4">\x00</span><span class="c10">' cargada en la dirección</span> <span class="c4">0x18000</span><span class="c1">:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 616.20px; height: 78.20px;"![image13](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/bc0dfebf-4dbc-4ce0-b2fa-faabec9e9151)
></span>

*   <span class="c10">Extraemos el marco de página de PTE y lo multiplicamos por</span> <span class="c10 c20">0x1000</span>

*   <span class="c4 c20">0x1a2f7e</span><span class="c10">→</span> <span class="c4 c8">dirección física</span>
*   <span class="c4 c20">0x18000</span><span class="c10">→</span> <span class="c4">dirección virtual</span>

<span class="c1"></span>

<span class="c1">Realizando un dumpeo de las 2 direcciones deberíamos obtener los mismos datos, ya que en realidad estaríamos accediendo al mismo espacio físico, bien mediante traducción o bien de forma directa.</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: -0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 615.20px; height: 246.13px;">![image2](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/12a0b9a7-5167-4d15-95ca-6d10742e539f)
</span>

<span class="c10">Por lo tanto realmente podemos calcular la página física de la dirección virtual en tiempo de ejecución, y si aprovechamos para que el marco de página de la PTE de 2 direcciones virtuales diferentes apuntarán al mismo</span> <span class="c4">pfn</span><span class="c1">??:</span>

<span class="c1"></span>

*   <span class="c13 c14 c20">Reservamos 2 espacios de memoria en user</span>
*   <span class="c13 c14 c20">En uno de ellos lo rellenamos de nuestro payload y en el otro de código benigno</span>
*   <span class="c13 c14 c20">Desde el driver obtenemos los correspondientes pfn de las PTE de las VA</span>
*   <span class="c14 c20">Y sobre-escribimos para el pfn de la</span> <span class="c14 c20">página</span><span class="c13 c14 c20"> con el payload por el pfn del código benigno</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px 0.00px; border: 0.00px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 561.47px; height: 213.80px;">![image19](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/f8a5e39c-aad0-4e77-90ea-5c8aee386740)
</span>

<span class="c1"></span>

<span class="c1">Trato de explicar en el diagrama anterior como sería la técnica que tratamos, de tal forma que “des-referenciamos” esa página física de su PTE, lo cual requerirá el recuperarla cuando se quiera acceder a ella.</span>

<span class="c13 c18 c8">5.-DRIVER</span>

<span class="c10">Lo primero que haremos es reservar memoria para escribir nuestra shellcode en memoria y reservar otro espacio de memoria de las mismas características con un sleed de</span> <span class="c4">0x42</span><span class="c1"> como zona de memoria benigna, después obtendremos la PTE con su PFN correspondiente de la misma forma que explique con el diagrama del punto 2 del write.</span>

<span class="c1"></span>

<span class="c10">Si bien existe una API en</span> <span class="c10 c21">nstoskrnl.exe</span><span class="c10">llamada</span> <span class="c4">nt!</span><span class="c4">MiGetPteAddress</span><span class="c10">que en el desplazamiento</span> <span class="c4">0x13</span><span class="c1"> contiene la base de los PTE:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 593.40px; height: 111.87px;">![](images/image23.png)</span>

<span class="c10">Nosotros llegaremos extrayendo el valor</span> <span class="c4">CR3</span><span class="c10">del</span> <span class="c4">EPROCESS</span><span class="c1"> y escalando hasta PTE:</span>

<span class="c1"></span>

*   <span class="c13 c4 c16">PML4E → PDPT → PD →  PDE → PTE [PFN]</span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c18">5.1-TÉCNICA</span><span class="c13 c18 c8"> ANTI-FORENSE FASE 1</span>

<span class="c10">Reservamos 2 espacios en memoria en uno de ellos escribimos la shellcode descifrada y en el otro lo rellenamos de</span> <span class="c4">0x42</span><span class="c10">. Obtenemos la dirección virtual de la shellcode del tamaño</span> <span class="c4">0x1000</span><span class="c10">que en nuestro caso se reserva en</span> <span class="c4">0x18000</span><span class="c10">y seremos su PTE  a</span> <span class="c4 c8">0000000000000000</span><span class="c10 c8">, y la dirección de la memoria limpia en</span> <span class="c4 c8">0x19000</span><span class="c10 c8">con un tamaño también de</span> <span class="c4 c8">0x1000</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px 0.00px; border: 0.00px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 627.53px; height: 242.00px;">![image17](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/7d82593c-0948-437f-b2f1-5d5892f70a98)
</span>

<span class="c1"></span>

<span class="c10">Intento representar en el diagrama la primera fase, recordar que el PFN de la PTE multiplicado por</span> <span class="c4">0x1000</span><span class="c1"> nos devuelve la dirección física real de tal forma que podemos volcar el contenido y mostramos con windbg:</span>

<span class="c1"></span>

*   <span class="c4 c16">0x18000</span> <span class="c10 c16">→ (0x6a1cb*0x1000) =</span> <span class="c4 c8">DIR.FISICA</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 631.07px; height: 320.93px;">![image3](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/e76f336a-226d-4cc6-af96-eca8b0d6b079)
</span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c10">Podemos observar como el volcado de la dirección física</span> <span class="c4">0x6a1cb000</span><span class="c10">que es la dirección virtual</span> <span class="c4">0x18000</span><span class="c10">contiene la shellcode descifrada con la clave</span> <span class="c4">RajKit</span><span class="c1"> mediante XOR, lo podemos ver en el debugger en el mapa de memoria:</span>

*   <span class="c4 c16">shellcode[i]^[</span><span class="c4 c16">RajKit</span><span class="c13 c4 c16">(i)]</span>

<span class="c13 c4 c8"></span>

<span class="c13 c4 c8"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 623.80px; height: 337.27px;">![image24](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/88234237-c649-4712-94ed-da4e699efd48)
</span>

<span class="c18">5.2-TÉCNICA</span><span class="c13 c18 c8"> ANTI-FORENSE FASE 2</span>

<span class="c10">En la segunda fase asignamos un PFN a la PTE de la dirección virtual que apunta a la página que contiene codigo benigno</span> <span class="c4">0x42</span><span class="c1"> y mantendremos oculta la shellcode:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px 0.00px; border: 0.00px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 591.87px; height: 232.20px;">![image7](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/4d7f9ec2-57bf-4639-98e7-8c83cf979438)
</span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c10">Lo vemos desde el windbg como el volcado del</span> <span class="c4">PFN 0x35815</span><span class="c10">que en realidad es la dirección física</span> <span class="c4">0x35815000</span><span class="c1"> no contiene la shellcode:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: -0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 621.60px; height: 61.67px;">![image18](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/912b0b62-99f6-4fa4-b611-9c88151a604c)
</span>

<span style="overflow: hidden; display: inline-block; margin: -0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 625.27px; height: 130.07px;">![image19](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/d3648de6-28be-43b3-9fb0-aa4448437848)
</span>

<span class="c10">Vemos como volcamos la dirección virtual de la shellcode que si obtenemos su PFN nos devuelve la PTE y si traducimos esa PTE nos devuelve la dirección</span> <span class="c4">0x18000</span><span class="c10"> que a su vez haciendo el volcado en realidad contiene un sleep de “</span><span class="c4">0x42</span><span class="c1">”:</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 623.07px; height: 393.53px;">![image15](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/358e957b-5248-422c-813d-3b46bc6384bb)
</span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c18">5.3-TÉCNICA</span><span class="c13 c8 c18"> ANTI-FORENSE FASE 3</span>

<span class="c1">En la fase 3 revertimos la ocultación de la shellcode, apuntaremos con un hilo de ejecución para ejecutarla y volvemos a ocultar en la memoria de la misma forma:</span>

<span class="c1"></span>

<span class="c10">Esto nos ejecutara una shellcode que abrirá</span> <span class="c10 c21">calc.exe</span><span class="c1"> para después volver a ocultarla:</span><span style="overflow: hidden; display: inline-block; margin: 0.00px 0.00px; border: 0.00px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 611.47px; height: 248.07px;">![image10](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/84fe4e27-2909-4f33-823d-dcf65d40326d)
</span>

<span class="c1"></span>

<span style="overflow: hidden; display: inline-block; margin: 0.00px -0.00px; border: 1.33px solid #000000; transform: rotate(0.00rad) translateZ(0px); -webkit-transform: rotate(0.00rad) translateZ(0px); width: 617.27px; height: 412.20px;">![image8](https://github.com/kdRajKit/KERNEL-HIDING/assets/108155637/7ac267d3-7301-4417-bffc-6fc400e0510b)
</span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c1"></span>

<span class="c13 c18 c8">6.-FUENTES</span>

<span class="c1"></span>

*   <span class="c19 c14">[https://lsi.vc.ehu.eus/pablogn/docencia/manuales/SO/TemasSOuJaen/ADMINISTRACIONDELAMEMORIA/5.1Paginacion.htm](https://www.google.com/url?q=https://lsi.vc.ehu.eus/pablogn/docencia/manuales/SO/TemasSOuJaen/ADMINISTRACIONDELAMEMORIA/5.1Paginacion.htm&sa=D&source=editors&ust=1709477008671919&usg=AOvVaw1dWmxfbLq4NrwIUkF-1ZdS)</span>
*   <span class="c19 c14">[https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/](https://www.google.com/url?q=https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/&sa=D&source=editors&ust=1709477008672432&usg=AOvVaw0hkn3Bj0dq9RRDhYKam3ft)</span>
*   <span class="c19 c14">[https://empyreal96.github.io/nt-info-depot/Windows-Internals-PDFs/WindowsSystemInternalPart1.pdf](https://www.google.com/url?q=https://empyreal96.github.io/nt-info-depot/Windows-Internals-PDFs/WindowsSystemInternalPart1.pdf&sa=D&source=editors&ust=1709477008672802&usg=AOvVaw3GwUcpYNt1XU9PwuEwiBEJ)</span>
*   <span class="c19 c14">[https://stackoverflow.com/questions/35670045/accessing-user-mode-memory-inside-kernel-mode-driver](https://www.google.com/url?q=https://stackoverflow.com/questions/35670045/accessing-user-mode-memory-inside-kernel-mode-driver&sa=D&source=editors&ust=1709477008673033&usg=AOvVaw3OG23d_N1DgLyofGZNoszS)</span>
*   <span class="c14 c19">[https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/kernel-mode-extensions](https://www.google.com/url?q=https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/kernel-mode-extensions&sa=D&source=editors&ust=1709477008673224&usg=AOvVaw0rbFP_DCgHOOyqznv_S8Ek)</span>
