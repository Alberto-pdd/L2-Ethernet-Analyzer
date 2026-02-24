/*
 * Autores: Alberto Palomo Dillana, Samuel González Martín
 * Grupo: Grupo 9
 * Fecha: 24/02/2026
 * Implementación de la Sesión: Gestión de interfaces de red mediante la librería pcap: 
 *                              listado, validación y extracción de la dirección física (MAC).
 */

//============================================================================
// ----------- PRACTICAS DE FUNDAMENTOS DE REDES DE COMUNICACIONES -----------
// ---------------------------- CURSO 2025/26 --------------------------------
// ----------------------------- SESION1.CPP ---------------------------------
//============================================================================

#include <stdio.h>
#include <iostream>
#include "linkLayer.h"

using namespace std;

void validarInterfaces(pcap_if_t *avail_ifaces);
void printInterfacesDisponibles(pcap_if_t *avail_ifaces);
void seleccionarInterfaz(int &seleccionada);
void printInterfazElegida(int seleccionada, pcap_if_t *avail_ifaces, interface_t &iface);

int main()
{
    // Estructura que almacenará los datos de la capa de enlace (nombre, MAC, etc.)
    // Iniciamos a 0 para no tener problemas con datos basura en el sistema
    interface_t iface = {0};

    // Puntero para gestionar la lista enlazada de interfaces detectadas por pcap
    pcap_if_t *avail_ifaces=NULL;
    
    // 1. Obtencion de la lista enlazada de dispositivos
    avail_ifaces=GetAvailAdapters(); 

    // 2. Control para evitar fallos de segmentación
    validarInterfaces(avail_ifaces);
 
    // 3. Salida de datos para informar al usuario de los dispositivos hallados
    printInterfacesDisponibles(avail_ifaces);

    // 4. Captura y validación del índice de interfaz deseada
    int seleccionada = -1;
    seleccionarInterfaz(seleccionada);

    // 5. Búsqueda final, resolución de nombre y visualización de MAC
    printInterfazElegida(seleccionada, avail_ifaces, iface);

    return 0;
}

//---------------------
// MÉTODOS AUXILIARES
//---------------------

/** Verifica la existencia de dispositivos de red.
 * 
 * @param avail_ifaces Puntero a la lista de interfaces obtenidas.
 * 
 * Si el puntero es nulo, significa que la librería pcap no pudo encontrar
 * adaptadores (por falta de permisos o ausencia de hardware). En tal caso,
 * se informa al usuario y se aborta la ejecución con exit(1) para evitar
 * accesos a memoria nula (error de null pointer).
 */
void validarInterfaces(pcap_if_t *avail_ifaces) {
    if(avail_ifaces == NULL) {
        cout << "Error: No se encontraron interfaces" << endl;
        exit(1);
    }
}

/** Muestra por pantalla la lista de adaptadores de red detectados.
 * 
 * @param avail_ifaces Puntero al inicio de la lista de interfaces.
 *
 * El método recorre la lista enlazada utilizando un bucle while hasta que el 
 * puntero es NULL. Para cada nodo, imprime un índice incremental ([1], [2], [3], ...) 
 * y el identificador del dispositivo (name), facilitando la selección posterior por 
 * parte del usuario.
 */
void printInterfacesDisponibles(pcap_if_t *avail_ifaces) {
    cout << "Interfaces disponibles:" << endl;
    int cont = 0;
    while(avail_ifaces != NULL) {
        cout << "[" << cont << "] " << avail_ifaces->name << endl;
        avail_ifaces = avail_ifaces->next;
        cont++;
    }
}

/** Gestiona la entrada del usuario para elegir una interfaz de la lista.
 * 
 * @param seleccionada Referencia al entero donde se almacenará el índice elegido.
 * 
 * El método emplea un bucle while (mediante la bandera 'pedir') que obliga
 * al usuario a introducir un número dentro del rango permitido [0-9].
 * Al usar paso por referencia (&), el valor capturado se actualiza directamente en
 * la variable original de la función main para poder usarla en módulos posteriores.
 */
void seleccionarInterfaz(int &seleccionada) {
    cout << "Seleccione interfaz: " << endl;
    bool pedir = true;

    while (pedir){
        cin >> seleccionada;
        if (seleccionada >= 0 && seleccionada <= 9)
        {
            pedir = false;
        }
        else
        {
            cout << "Numero invalido, inserte uno correcto" << endl;
        }  
    }
}

/** Localiza la interfaz seleccionada, obtiene su dirección MAC y la muestra.
 * 
 * @param seleccionada Índice numérico elegido por el usuario.
 * @param avail_ifaces Puntero a la lista de dispositivos (se recorre para buscar el nombre).
 * @param iface Referencia a la estructura donde se almacenarán los datos de la interfaz física.
 * 
 * El método realiza tres pasos críticos:
 * 1. Búsqueda: Recorre la lista enlazada hasta alcanzar el nodo correspondiente al índice.
 * 2. Enlace: Configura el nombre del dispositivo en la estructura 'iface' y consulta la MAC.
 * 3. Formateo: Traduce los 6 bytes de la MAC de formato binario a hexadecimal legible (XX:XX:XX:XX:XX:XX).
 */
void printInterfazElegida(int seleccionada, pcap_if_t *avail_ifaces, interface_t &iface) {
    avail_ifaces=GetAvailAdapters();

    // 1. Busqueda
    cout << "Interfaz Elegida: ";
    for(int i = 0; i < seleccionada; i++) {
        if(avail_ifaces->next != NULL) {
            avail_ifaces = avail_ifaces->next;
        }
    }
    cout << avail_ifaces->name << endl;

    // 2. Enlace
    setDeviceName(&iface, avail_ifaces->name);
    GetMACAdapter(&iface);

    // 3. Formateo / Mostrar
    cout << "La MAC es: ";
    unsigned char macAddrs[6];
    for (int i = 0; i < 6; i++) {
        macAddrs[i] = iface.MACaddr[i];

        printf("%02X", macAddrs[i]);
        if(i < 5) printf(":");
    }
    cout << endl;
}