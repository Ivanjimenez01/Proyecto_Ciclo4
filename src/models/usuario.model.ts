import {Entity, hasMany, model, property} from '@loopback/repository';
import {Pedido} from './pedido.model';

@model()
export class Usuario extends Entity {
  @property({
    type: 'string',
    id: true,
    generated: true,
  })
  id?: string;

  @property({
    type: 'string',
    required: true,
  })
  nombres: string;

  @property({
    type: 'string',
    required: true,
  })
  apellidos: string;

  @property({
    type: 'string',
    required: true,
  })
  celular: string;

  @property({
    type: 'string',
    required: true,
  })
  cuidad: string;

  @property({
    type: 'string',
    required: true,
  })
  correo: string;

  @property({
    type: 'string',
    required: true,
  })
  direccion: string;
/*
  @property({
    type: 'string',
    required: false,
  })
  clave: string;
*/
  @property({
    type: 'string',
    required: true,
  })
  rol: string;

  @property({         //arreglo
    type: 'string',
    required: false,
  })
  clave: string;       //fin del arreglo

  @hasMany(() => Pedido)
  pedidos: Pedido[];

  constructor(data?: Partial<Usuario>) {
    super(data);
  }
}

export interface UsuarioRelations {
  // describe navigational properties here
}

export type UsuarioWithRelations = Usuario & UsuarioRelations;
