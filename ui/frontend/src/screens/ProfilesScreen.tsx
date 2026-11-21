import { Layers3, Plus } from "lucide-react";
import { useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { StatusBadge } from "../components/StatusBadge";

type Profile = {
  id: number;
  name: string;
  description: string;
  targets: number;
};

const initialProfiles: Profile[] = [
  { id: 1, name: "Стандартный", description: "Основной профиль для повседневной работы", targets: 6 },
  { id: 2, name: "Наблюдение", description: "Демонстрационный режим без изменений", targets: 3 },
];

export function ProfilesScreen() {
  const [profiles, setProfiles] = useState(initialProfiles);
  const [activeId, setActiveId] = useState(1);

  const addDemoProfile = () => {
    const id = Math.max(...profiles.map((profile) => profile.id)) + 1;
    setProfiles((current) => [
      ...current,
      { id, name: `Новый профиль ${id - 1}`, description: "Локальная демонстрационная запись", targets: 0 },
    ]);
  };

  return (
    <div className="screen">
      <PageHeader
        title="Профили"
        description="Локальные наборы параметров интерфейса"
        action={
          <button className="secondary-button" type="button" onClick={addDemoProfile}>
            <Plus size={14} />Новый профиль
          </button>
        }
      />

      <div className="profile-list">
        {profiles.map((profile) => {
          const active = profile.id === activeId;
          return (
            <article className={`profile-card${active ? " profile-card--active" : ""}`} key={profile.id}>
              <div className="profile-card__icon"><Layers3 size={17} strokeWidth={1.7} /></div>
              <div className="profile-card__copy">
                <div className="profile-card__title">
                  <strong>{profile.name}</strong>
                  {active && <StatusBadge tone="accent">Активный</StatusBadge>}
                </div>
                <p>{profile.description}</p>
                <small>{profile.targets} целей</small>
              </div>
              {!active && (
                <button className="quiet-button" type="button" onClick={() => setActiveId(profile.id)}>
                  Выбрать
                </button>
              )}
            </article>
          );
        })}
      </div>

      <p className="local-note">Профили пока демонстрационные и не меняют работу движка.</p>
    </div>
  );
}
