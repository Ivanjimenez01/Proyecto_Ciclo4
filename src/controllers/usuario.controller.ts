import {service} from '@loopback/core';
import {
  Count,
  CountSchema,
  Filter,
  FilterExcludingWhere,
  repository,
  Where
} from '@loopback/repository';
import {
  del, get,
  getModelSchemaRef, HttpErrors, param, patch, post, put, requestBody,
  response
} from '@loopback/rest';
import {Llaves} from '../config/llaves';
import {Credenciales, Usuario} from '../models';
import {UsuarioRepository} from '../repositories';
import {AutenticacionService} from '../services';
const fetch = require('node-fetch');

export class UsuarioController {
  constructor(
    @repository(UsuarioRepository)
    public usuarioRepository: UsuarioRepository,
    @service(AutenticacionService)
    public servicioAutenticacion: AutenticacionService
  ) { }
  //anexo cambio de actualizacion clave de usuario por parte del mismo.
  //actualizacion de la clave generada por el usuario
  
  @post('/actualizacionClaveByUsuario', {
    responses: {
      '200': {
        description: "Actualizacion de clave por parte del usuario"
      }
    }
  })
  async actualizarClavebyUsuario(
    @requestBody() credenciales: Credenciales
  ) {
    let clave = credenciales.clave;
    let claveCifrada = this.servicioAutenticacion.CifrarClave(clave);
    let usuarioEncontrado = await this.usuarioRepository.findOne({where: {correo: credenciales.usuario}});
    if (usuarioEncontrado != null) {
      usuarioEncontrado.clave = claveCifrada;
      let id = usuarioEncontrado.id;
      let destino = usuarioEncontrado.correo;
      let asunto = 'Confirmacion de clave';
      await this.usuarioRepository.updateById(id, usuarioEncontrado);
      let contenido = `Hola ${usuarioEncontrado.nombres} ${usuarioEncontrado.apellidos}, su nombre de usuario es: ${usuarioEncontrado.correo} y la contraseña asignada por usted es: ${clave}. Recuerde que su tipo de rol es ${usuarioEncontrado.rol}.`
      //fetch(`http://127.0.0.1:5000/envio-correo?correo_destino=${destino}&asunto=${asunto}&contenido=${contenido}`)
      fetch(`${Llaves.urlServicioNotificaciones}/envio-correo?correo_destino=${destino}&asunto=${asunto}&contenido=${contenido}`)
        .then((data: any) => {
          console.log(data);
        })
      let destinoCel = usuarioEncontrado.celular;
      fetch(`${Llaves.urlServicioNotificaciones}/sms?telefono=${destinoCel}&mensaje=${contenido}`)
        .then((data: any) => {
          console.log(data);
        })
      return usuarioEncontrado;
    } else {
      throw new HttpErrors[401]("Usuario invalido");
    }
  }
  //actualizacion de la clave generada por el sistema
  @post('/actualizacionClaveBySystem', {
    responses: {
      '200': {
        description: "Actualizacion de clave"
      }
    }
  })
  async actualizarClave(
    @requestBody() credenciales: Omit<Credenciales, 'clave'>
  ) {
    let clave = this.servicioAutenticacion.GenerarClave();
    let claveCifrada = this.servicioAutenticacion.CifrarClave(clave);
    let usuarioEncontrado = await this.usuarioRepository.findOne({where: {correo: credenciales.usuario}});
    if (usuarioEncontrado != null) {
      usuarioEncontrado.clave = claveCifrada;
      let id = usuarioEncontrado.id;
      let destino = usuarioEncontrado.correo;
      let asunto = 'Actualizacion de clave de usuario';
      await this.usuarioRepository.updateById(id, usuarioEncontrado);
      let contenido = `Hola ${usuarioEncontrado.nombres} ${usuarioEncontrado.apellidos}, su nombre de usuario es: ${usuarioEncontrado.correo} y su nueva contraseña es: ${clave}. Recuerde que su tipo de rol es ${usuarioEncontrado.rol}.`
      //fetch(`http://127.0.0.1:5000/envio-correo?correo_destino=${destino}&asunto=${asunto}&contenido=${contenido}`)
      fetch(`${Llaves.urlServicioNotificaciones}/envio-correo?correo_destino=${destino}&asunto=${asunto}&contenido=${contenido}`)
        .then((data: any) => {
          console.log(data);
        })
      let destinoCel = usuarioEncontrado.celular;
      fetch(`${Llaves.urlServicioNotificaciones}/sms?telefono=${destinoCel}&mensaje=${contenido}`)
        .then((data: any) => {
          console.log(data);
        })
      return usuarioEncontrado;
    } else {
      throw new HttpErrors[401]("Usuario invalido");
    }
  }

  //fin anexo actualizacion clave por usuario

  @post("/identificarUsuario", {
    responses: {
      '200': {
        description: "identificacion de usuarios"
      }
    }
  })

  async identificarUsuario(
    @requestBody() credenciales: Credenciales
  ) {
    let u = await this.servicioAutenticacion.IdentificarUsuario(credenciales.usuario, credenciales.clave);
    if (u) {
      let token = this.servicioAutenticacion.GenerarTokenJWT(u);
      return {
        datos: {
          nombre: u.nombres,
          correo: u.correo,
          rol: u.rol,
          id: u.id,
        },
        tk: token
      }
    } else {
      throw new HttpErrors[401]("Datos invalidos");
    }
  }

  @post('/usuarios')
  @response(200, {
    description: 'Usuario model instance',
    content: {'application/json': {schema: getModelSchemaRef(Usuario)}},
  })
  async create(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {
            title: 'NewUsuario',
            exclude: ['id'],
          }),
        },
      },
    })
    usuario: Omit<Usuario, 'id'>,
  ): Promise<Usuario> {

    let clave = this.servicioAutenticacion.GenerarClave();
    let claveCifrada = this.servicioAutenticacion.CifrarClave(clave);
    usuario.clave = claveCifrada;
    let u = await this.usuarioRepository.create(usuario);

    //notificar al usuario
    let destino = usuario.correo;
    let asunto = 'Registro en la plataforma';
    let contenido = `Hola ${usuario.nombres} ${usuario.apellidos}, su nombre de usuario es: ${usuario.correo} y su contraseña es: ${clave}. Recuerde que su rol de usuario es: ${usuario.rol}`
    fetch(`${Llaves.urlServicioNotificaciones}/envio-correo?correo_destino=${destino}&asunto=${asunto}&contenido=${contenido}`)
      .then((data: any) => {
        console.log(data);
      })

    let destinoCel = usuario.celular;
    fetch(`${Llaves.urlServicioNotificaciones}/sms?telefono=${destinoCel}&mensaje=${contenido}`)
      .then((data: any) => {
        console.log(data);
      })

    return u;


  }

  @get('/usuarios/count')
  @response(200, {
    description: 'Usuario model count',
    content: {'application/json': {schema: CountSchema}},
  })
  async count(
    @param.where(Usuario) where?: Where<Usuario>,
  ): Promise<Count> {
    return this.usuarioRepository.count(where);
  }

  @get('/usuarios')
  @response(200, {
    description: 'Array of Usuario model instances',
    content: {
      'application/json': {
        schema: {
          type: 'array',
          items: getModelSchemaRef(Usuario, {includeRelations: true}),
        },
      },
    },
  })
  async find(
    @param.filter(Usuario) filter?: Filter<Usuario>,
  ): Promise<Usuario[]> {
    return this.usuarioRepository.find(filter);
  }

  @patch('/usuarios')
  @response(200, {
    description: 'Usuario PATCH success count',
    content: {'application/json': {schema: CountSchema}},
  })
  async updateAll(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {partial: true}),
        },
      },
    })
    usuario: Usuario,
    @param.where(Usuario) where?: Where<Usuario>,
  ): Promise<Count> {
    return this.usuarioRepository.updateAll(usuario, where);
  }

  @get('/usuarios/{id}')
  @response(200, {
    description: 'Usuario model instance',
    content: {
      'application/json': {
        schema: getModelSchemaRef(Usuario, {includeRelations: true}),
      },
    },
  })
  async findById(
    @param.path.string('id') id: string,
    @param.filter(Usuario, {exclude: 'where'}) filter?: FilterExcludingWhere<Usuario>
  ): Promise<Usuario> {
    return this.usuarioRepository.findById(id, filter);
  }

  @patch('/usuarios/{id}')
  @response(204, {
    description: 'Usuario PATCH success',
  })
  async updateById(
    @param.path.string('id') id: string,
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {partial: true}),
        },
      },
    })
    usuario: Usuario,
  ): Promise<void> {
    await this.usuarioRepository.updateById(id, usuario);
  }

  @put('/usuarios/{id}')
  @response(204, {
    description: 'Usuario PUT success',
  })
  async replaceById(
    @param.path.string('id') id: string,
    @requestBody() usuario: Usuario,
  ): Promise<void> {
    await this.usuarioRepository.replaceById(id, usuario);
  }

  @del('/usuarios/{id}')
  @response(204, {
    description: 'Usuario DELETE success',
  })
  async deleteById(@param.path.string('id') id: string): Promise<void> {
    await this.usuarioRepository.deleteById(id);
  }
}
