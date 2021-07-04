
#ifndef PROTOVERSE_ENTITY_H
#define PROTOVERSE_ENTITY_H

#include "resource.h"

typedef struct resource_id entity_id;

enum entity_type {
	ENT_AVATAR,
	ENT_OBJECT,
};

struct entity {
	const char *name;
	enum entity_type type;
	int cell;
	double pos[3];
};

static inline const char *entity_name(struct env *env, entity_id *id)
{
	struct entity *ent;

	if (!(ent = get_resource(&env->entities, id))) {
		return "unknown";
	}

	return ent->name;
}


#endif /* PROTOVERSE_ENTITY_H */
